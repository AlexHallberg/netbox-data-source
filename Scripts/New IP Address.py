"""
New IP Address -- NetBox custom script.

Issues the next free IP address at a site to a network endpoint. The helpdesk
picks a site and a prefix role; the script resolves the single site prefix
carrying that role and takes the first free address in it.

The address is then recorded with the mask of the network the endpoint is
actually configured on, not the mask of the site prefix it was drawn from. A
/24 carved out of a /16 for site bookkeeping is not a broadcast domain of its
own, so an address drawn from it is stored as a /16.

Both the mask and the gateway come from the HSRP address serving the site
prefix -- an IP address in NetBox with role HSRP, found in the site prefix's own
prefix hierarchy (normally on the /16 supernet). That address is a real host on
the network, so the mask it is recorded with is by definition the mask its
endpoints use. Nothing about the addressing is hardcoded here.

Widening the mask does not disturb the site prefix's bookkeeping: NetBox matches
child IPs to a prefix by host containment (`address__host_between`), not by mask
length, so the /16-masked address still counts against the /24's available-IP
list and utilization.

Written for NetBox 4.6.
"""

import re

import netaddr
from django.core.exceptions import ValidationError
from django.db import transaction

from dcim.models import Site
from extras.models import CustomField
from extras.scripts import ChoiceVar, ObjectVar, Script, StringVar
from ipam.choices import (
    IPAddressRoleChoices,
    IPAddressStatusChoices,
    PrefixStatusChoices,
)
from ipam.models import IPAddress, Prefix, Role
from utilities.exceptions import AbortScript


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

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


def resolveGateway(prefix):
    """
    Return the HSRP address serving the given site prefix.

    Candidates are IP addresses with role HSRP anywhere in the prefix's own
    hierarchy, itself included. A candidate only counts if the network it is
    configured on actually covers the site prefix -- that rejects a gateway
    sitting in a wider ancestor but belonging to a different broadcast domain,
    and it rejects a gateway mistakenly recorded as a /32.
    """
    prefixNetwork = netaddr.IPNetwork(str(prefix.prefix))

    candidates = {}
    for ancestor in prefix.get_parents(include_self=True):
        hsrpAddresses = ancestor.get_child_ips().filter(
            role=IPAddressRoleChoices.ROLE_HSRP
        )
        for address in hsrpAddresses:
            candidates[address.pk] = address

    serving = [
        address for address in candidates.values()
        if prefixNetwork in netaddr.IPNetwork(str(address.address)).cidr
    ]

    if not serving:
        if candidates:
            detail = (
                f"HSRP addresses exist in the hierarchy but none covers this "
                f"prefix: {', '.join(str(a.address) for a in candidates.values())}."
            )
        else:
            detail = "No HSRP addresses exist anywhere in this prefix's hierarchy."
        raise AbortScript(
            f"No HSRP address serves {prefix.prefix}, so the endpoint mask and "
            f"gateway are unknown. Record the gateway in NetBox as an IP address "
            f"with role HSRP, carrying the mask its endpoints are configured "
            f"with (e.g. 10.111.0.1/16), in the same VRF. {detail}"
        )

    if len(serving) > 1:
        found = ', '.join(str(address.address) for address in serving)
        raise AbortScript(
            f"Found {len(serving)} HSRP addresses serving {prefix.prefix}: "
            f"{found}. Exactly one is needed to determine the endpoint mask and "
            f"gateway. Resolve this in NetBox before issuing addresses."
        )

    return serving[0]


# ---------------------------------------------------------------------------
# Script
# ---------------------------------------------------------------------------

class NewIPAddress(Script):

    class Meta:
        name = "New IP Address"
        description = (
            "Issue the next free IP address at a site to a network endpoint."
        )
        # NB: no variable below may be called 'description', 'name', 'module',
        # 'class_name', 'full_name' or 'filename' -- those are classproperties on
        # BaseScript, and shadowing one breaks the whole script list page.
        field_order = (
            'site', 'role', 'macAddress', 'dnsName', 'ipDescription', 'status',
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
            "Prefix role describing what the endpoint is, e.g. CTS. Each site "
            "has one prefix per role."
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
    ipDescription = StringVar(
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

        gatewayAddress = resolveGateway(prefix)
        gatewayNetwork = netaddr.IPNetwork(str(gatewayAddress.address))
        gateway = gatewayNetwork.ip
        endpointNetwork = gatewayNetwork.cidr

        self.log_info(
            f"Gateway {gatewayAddress.address} serves {prefix.prefix}, so the "
            f"endpoint belongs to {endpointNetwork} and is recorded as "
            f"/{endpointNetwork.prefixlen}.",
            obj=gatewayAddress,
        )

        if endpointNetwork == netaddr.IPNetwork(str(prefix.prefix)):
            self.log_warning(
                f"The gateway's network is the site prefix itself, so the mask "
                f"was not widened. Check that {gatewayAddress.address} carries "
                f"the mask its endpoints are configured with.",
                obj=gatewayAddress,
            )

        if WARN_ON_DUPLICATE_MAC:
            self.warnOnDuplicateMac(macAddress)

        ipAddress = self.allocateAddress(
            prefix, endpointNetwork, gateway, macAddress, data
        )

        if not commit:
            self.log_warning(
                "Commit is disabled, so the address above was rolled back and "
                "is still free."
            )

        return (
            f"**{ipAddress.address}** issued to `{macAddress}`\n\n"
            f"- Gateway: {gateway}\n"
            f"- Subnet mask: {endpointNetwork.netmask}\n"
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
        A supernet scoped to a region populates `_region` and leaves `_site`
        null, so it is never picked up here even when it shares the role.
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

    def allocateAddress(self, prefix, endpointNetwork, gateway, macAddress, data):
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
            address = f'{host}/{endpointNetwork.prefixlen}'

            ipAddress = IPAddress(
                address=address,
                status=data['status'],
                vrf=lockedPrefix.vrf,
                dns_name=data['dnsName'] or '',
                description=data['ipDescription'],
            )
            ipAddress.custom_field_data.update({
                CF_MAC_ADDRESS: macAddress,
                CF_GATEWAY: str(gateway),
                CF_SUBNET_MASK: str(endpointNetwork.netmask),
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
