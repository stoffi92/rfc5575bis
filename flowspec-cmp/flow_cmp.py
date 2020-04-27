"""
Copyright (c) 2020 IETF Trust and the persons identified as authors
of draft-ietf-idr-rfc5575bis. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, is permitted pursuant to, and subject to the license
terms contained in, the Simplified BSD License set forth in Section
4.c of the IETF Trust’s Legal Provisions Relating to IETF Documents
(http://trustee.ietf.org/license-info).
"""

import itertools
import collections
import ipaddress


EQUAL = 0
A_HAS_PRECEDENCE = 1
B_HAS_PRECEDENCE = 2
IP_DESTINATION = 1
IP_SOURCE = 2

FS_component = collections.namedtuple('FS_component',
                                      'component_type op_value')


class FS_nlri(object):
    """
    FS_nlri class implementation that allows sorting.

    By calling .sort() on a array of FS_nlri objects these will be
    sorted according to the flow_rule_cmp algorithm.

    Example:
    nlri = [ FS_nlri(components=[
             FS_component(component_type=IP_DESTINATION,
                    op_value=ipaddress.ip_network('10.1.0.0/16') ),
             FS_component(component_type=4,
                    op_value=bytearray([0,1,2,3,4,5,6])),
             ]),
             FS_nlri(components=[
             FS_component(component_type=5,
                    op_value=bytearray([0,1,2,3,4,5,6])),
             FS_component(component_type=6,
                    op_value=bytearray([0,1,2,3,4,5,6])),
             ]),
           ]
    nlri.sort() # sorts the array accorinding to the algorithm
    """
    def __init__(self, components = None):
        """
        components: list of type FS_component
        """
        self.components = components

    def __lt__(self, other):
        # use the below algorithm for sorting
        result = flow_rule_cmp(self, other)
        if result == B_HAS_PRECEDENCE:
            return True
        else:
            return False


def flow_rule_cmp(a, b):
    """
    Example of the flowspec comparison algorithm.
    """
    for comp_a, comp_b in itertools.zip_longest(a.components,
                                           b.components):
        # If a component type does not exist in one rule
        # this rule has lower precedence
        if not comp_a:
            return B_HAS_PRECEDENCE
        if not comp_b:
            return A_HAS_PRECEDENCE
        # Higher precedence for lower component type
        if comp_a.component_type < comp_b.component_type:
            return A_HAS_PRECEDENCE
        if comp_a.component_type > comp_b.component_type:
            return B_HAS_PRECEDENCE
        # component types are equal -> type specific comparison
        if comp_a.component_type in (IP_DESTINATION, IP_SOURCE):
            # assuming comp_a.op_value, comp_b.op_value of
            # type ipaddress.IPv4Network
            if comp_a.op_value.overlaps(comp_b.op_value):
                # longest prefixlen has precedence
                if comp_a.op_value.prefixlen > \
                        comp_b.op_value.prefixlen:
                    return A_HAS_PRECEDENCE
                if comp_a.op_value.prefixlen < \
                        comp_b.op_value.prefixlen:
                    return B_HAS_PRECEDENCE
                # components equal -> continue with next component
            elif comp_a.op_value > comp_b.op_value:
                return B_HAS_PRECEDENCE
            elif comp_a.op_value < comp_b.op_value:
                return A_HAS_PRECEDENCE
        else:
            # assuming comp_a.op_value, comp_b.op_value of type
            # bytearray
            if len(comp_a.op_value) == len(comp_b.op_value):
                if comp_a.op_value > comp_b.op_value:
                    return B_HAS_PRECEDENCE
                if comp_a.op_value < comp_b.op_value:
                    return A_HAS_PRECEDENCE
                # components equal -> continue with next component
            else:
                common = min(len(comp_a.op_value), len(comp_b.op_value))
                if comp_a.op_value[:common] > comp_b.op_value[:common]:
                    return B_HAS_PRECEDENCE
                elif comp_a.op_value[:common] < \
                        comp_b.op_value[:common]:
                    return A_HAS_PRECEDENCE
                # the first common bytes match
                elif len(comp_a.op_value) > len(comp_b.op_value):
                    return A_HAS_PRECEDENCE
                else:
                    return B_HAS_PRECEDENCE
    return EQUAL
