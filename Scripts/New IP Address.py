"""
New IP Address -- NetBox custom script.

Issues the next free IP address at a site to a network endpoint. The helpdesk
picks a site and a prefix role; the script resolves the single site prefix
carrying that role, takes the first free address in it, and records the address
with the mask of the supernet the endpoint is actually configured with -- so an
address drawn from a /24 site prefix inside a /16 supernet is stored as a /16.

That works because NetBox matches child IPs to a prefix by host containment
(`address__host_between`), not by mask length: the /16-masked address still
counts against the /24's available-IP list and utilization.

Written for NetBox 4.6.
"""

import re

import netaddr
from django.core.exceptions import ValidationError
from django.db import transaction

from dcim.models import Site
from extras.models import CustomField
from extras.scripts import ChoiceVar, ObjectVar, Script, StringVar
from ipam.choices import IPAddressStatusChoices, PrefixStatusChoices
from ipam.models import IPAddress, Prefix, Role
from utilities.exceptions import AbortScript


# ---------------------------------------------------------------------------
# Configuration -- maintained by the network team, not by the helpdesk.
# ---------------------------------------------------------------------------

# Every supernet an endpoint address may belong to, with the gateway endpoints
# in it are configured with. The mask written onto the new address comes from
# the supernet's prefix length, and the gateway and subnet mask custom fields
# are filled from the matching entry.
#
# List site-local supernets (your /20s) here alongside the multi-site /16s. If
# entries overlap, the most specific match wins. A resolved site prefix that no
# entry covers aborts the script rather than guessing a mask.
#
# TODO: replace these examples with your real supernets.
SUPERNETS = [
    {'supernet': '10.1.0.0/16', 'gateway': '10.1.0.1'},
    {'supernet': '10.2.0.0/16', 'gateway': '10.2.0.1'},
    {'supernet': '172.20.16.0/20', 'gateway': '172.20.16.1'},
]

# Names (not labels) of the custom fields on ipam.IPAddress. The script checks
# these exist before touching anything and tells you the real names if not.
CF_MAC_ADDRESS = 'mac_address'
CF_GATEWAY = 'gateway'
CF_SUBNET_MASK = 'subnet_mask'

# Warn when the MAC is already recorded against another address, so the
# helpdesk can reuse the existing one instead of issuing a second.
WARN_ON_DUPLICATE_MAC = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalizeMacAddress(value):
    """Accept any common MAC notation and return it as AA:BB:CC:DD:EE:FF."""
    cleaned = re.sub(r'[\s:.\-]', '', value).upper()
    if not re.fullmatch(r'[0-9A-F]{12}', cleaned):
        raise AbortScript(
            f"'{value}' is not a valid MAC address. Expected 12 hex digits, "
            f"optionally separated by colons, hyphens or dots."
        )
    return ':'.join(cleaned[index:index + 2] for index in range(0, 12, 2))


def resolveSupernet(prefix):
    """
    Return the (network, gateway) pair from SUPERNETS that covers the prefix.

    The most specific match wins, so a site-local /20 listed alongside the /16
    it sits in behaves predictably.
    """
    prefixNetwork = netaddr.IPNetwork(str(prefix.prefix))
    matches = []

    for entry in SUPERNETS:
        try:
            supernetNetwork = netaddr.IPNetwork(entry['supernet'])
            gateway = netaddr.IPAddress(entry['gateway'])
        except (KeyError, ValueError, netaddr.AddrFormatError) as error:
            raise AbortScript(f"Malformed SUPERNETS entry {entry!r}: {error}")

        if gateway not in supernetNetwork:
            raise AbortScript(
                f"SUPERNETS is misconfigured: gateway {gateway} is not inside "
                f"{supernetNetwork}."
            )

        if prefixNetwork in supernetNetwork:
            matches.append((supernetNetwork, gateway))

    if not matches:
        raise AbortScript(
            f"{prefix.prefix} is not covered by any entry in SUPERNETS, so the "
            f"endpoint mask and gateway are unknown. Add the supernet to the "
            f"script configuration."
        )

    matches.sort(key=lambda match: match[0].prefixlen, reverse=True)
    return matches[0]


# ---------------------------------------------------------------------------
# Script
# ---------------------------------------------------------------------------

class NewIPAddress(Script):

    class Meta:
        name = "New IP Address"
        description = (
            "Issue the next free IP address at a site to a network endpoint."
        )
        field_order = (
            'site', 'role', 'macAddress', 'dnsName', 'description', 'status',
        )
        commit_default = True
        scheduling_enabled = False

    site = ObjectVar(
        model=Site,
        label="Site",
        description="Site the endpoint is connected at.",
    )
    role = ObjectVar(
        model=Role,
        label="Role",
        description=(
            "Prefix role describing what the endpoint is, e.g. Clients or "
            "Printers. Each site has one prefix per role."
        ),
    )
    macAddress = StringVar(
        label="MAC address",
        description=(
            "Any common notation, e.g. aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF "
            "or aabb.ccdd.eeff."
        ),
    )
    dnsName = StringVar(
        label="DNS name",
        description="Hostname for the endpoint. Leave blank if unknown.",
        required=False,
    )
    description = StringVar(
        label="Description",
        description="Who or what this address was issued to, and why.",
    )
    status = ChoiceVar(
        choices=IPAddressStatusChoices,
        default=IPAddressStatusChoices.STATUS_ACTIVE,
        label="Status",
    )

    def run(self, data, commit):
        self.validateCustomFields()

        macAddress = normalizeMacAddress(data['macAddress'])
        prefix = self.resolvePrefix(data['site'], data['role'])
        supernetNetwork, gateway = resolveSupernet(prefix)

        self.log_info(
            f"Allocating from {prefix.prefix}, recording the address as "
            f"/{supernetNetwork.prefixlen} on supernet {supernetNetwork}.",
            obj=prefix,
        )

        if WARN_ON_DUPLICATE_MAC:
            self.warnOnDuplicateMac(macAddress)

        ipAddress = self.allocateAddress(
            prefix, supernetNetwork, gateway, macAddress, data
        )

        if not commit:
            self.log_warning(
                "Commit is disabled, so the address above was rolled back and "
                "is still free."
            )

        return (
            f"**{ipAddress.address}** issued to `{macAddress}`\n\n"
            f"- Gateway: {gateway}\n"
            f"- Subnet mask: {supernetNetwork.netmask}\n"
            f"- Drawn from: {prefix.prefix} at {data['site']}"
        )

    def validateCustomFields(self):
        """Fail early and readably if the configured custom fields are missing."""
        available = {
            customField.name
            for customField in CustomField.objects.get_for_model(IPAddress)
        }
        missing = {CF_MAC_ADDRESS, CF_GATEWAY, CF_SUBNET_MASK} - available

        if missing:
            raise AbortScript(
                f"These custom fields are not defined on IP addresses: "
                f"{', '.join(sorted(missing))}. Fields that do exist: "
                f"{', '.join(sorted(available)) or '(none)'}. Correct the CF_* "
                f"names at the top of the script."
            )

    def resolvePrefix(self, site, role):
        """
        Return the single non-container prefix scoped to the site with this role.

        `_site` is the cached scope field behind NetBox's own `?site_id=` prefix
        filter, so this also matches prefixes scoped to a location in the site.
        """
        prefixes = list(
            Prefix.objects
            .filter(_site=site, role=role)
            .exclude(status=PrefixStatusChoices.STATUS_CONTAINER)
            .select_related('vrf')
        )

        if not prefixes:
            raise AbortScript(
                f"No prefix is scoped to {site} with role {role}. Container "
                f"prefixes are ignored, so check that the site prefix exists, "
                f"is scoped to the site or a location within it, carries this "
                f"role, and is not a container."
            )

        if len(prefixes) > 1:
            found = ', '.join(str(prefix.prefix) for prefix in prefixes)
            raise AbortScript(
                f"Expected one prefix for {site} with role {role} but found "
                f"{len(prefixes)}: {found}. Resolve this in NetBox before "
                f"issuing addresses."
            )

        return prefixes[0]

    def warnOnDuplicateMac(self, macAddress):
        duplicates = IPAddress.objects.filter(
            **{f'custom_field_data__{CF_MAC_ADDRESS}': macAddress}
        )
        for duplicate in duplicates:
            self.log_warning(
                f"{duplicate.address} is already recorded against MAC "
                f"{macAddress}. Check whether the endpoint should reuse it "
                f"instead of taking a second address.",
                obj=duplicate,
            )

    def allocateAddress(self, prefix, supernetNetwork, gateway, macAddress, data):
        with transaction.atomic():
            # Lock the prefix row so two people running this at the same moment
            # cannot be handed the same address.
            lockedPrefix = Prefix.objects.select_for_update().get(pk=prefix.pk)

            firstAvailable = lockedPrefix.get_first_available_ip()
            if firstAvailable is None:
                raise AbortScript(
                    f"{lockedPrefix.prefix} has no free addresses left."
                )

            # get_first_available_ip() returns the host carrying the *prefix's*
            # mask; rewrite it to the mask the endpoint is configured with.
            host = netaddr.IPNetwork(firstAvailable).ip
            address = f'{host}/{supernetNetwork.prefixlen}'

            ipAddress = IPAddress(
                address=address,
                status=data['status'],
                vrf=lockedPrefix.vrf,
                dns_name=data['dnsName'] or '',
                description=data['description'],
            )
            ipAddress.custom_field_data.update({
                CF_MAC_ADDRESS: macAddress,
                CF_GATEWAY: str(gateway),
                CF_SUBNET_MASK: str(supernetNetwork.netmask),
            })

            try:
                ipAddress.full_clean()
            except ValidationError as error:
                raise AbortScript(
                    f"NetBox rejected {address}: {'; '.join(error.messages)}"
                )

            ipAddress.save()

        self.log_success(f"Created {ipAddress.address}.", obj=ipAddress)
        return ipAddress
