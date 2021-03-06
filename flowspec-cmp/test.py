import unittest

from flow_cmp import *


class TestFlowCmp(unittest.TestCase):
    def test_different_listlength(self):
        a = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6])),
            FS_component(component_type=5, op_value=bytearray([0,1,2,3,4,5,6])),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6])),
            ])
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)

    def test_different_component_types(self):
        a = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6])),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=5, op_value=bytearray([0,1,2,3,4,5,6])),
            FS_component(component_type=6, op_value=bytearray([0,1,2,3,4,5,6])),
            ])
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)

    def test_equal_fs(self):
        a = FS_nlri(components=[
            FS_component(component_type=IP_DESTINATION, op_value=ipaddress.ip_network('10.1.0.0/16') ),
            FS_component(component_type=IP_SOURCE, op_value=ipaddress.ip_network('10.2.0.0/16') ),
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6])),
            FS_component(component_type=5, op_value=bytearray([0,1,2,3,4,5,6])),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=IP_DESTINATION, op_value=ipaddress.ip_network('10.1.0.0/16') ),
            FS_component(component_type=IP_SOURCE, op_value=ipaddress.ip_network('10.2.0.0/16') ),
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6])),
            FS_component(component_type=5, op_value=bytearray([0,1,2,3,4,5,6])),
            ])
        self.assertEqual(flow_rule_cmp(a, b), EQUAL)

    def test_ip_prefix_same_common(self):
        a = FS_nlri(components=[
            FS_component(component_type=IP_DESTINATION, op_value=ipaddress.ip_network('10.0.0.0/8') ),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=IP_DESTINATION, op_value=ipaddress.ip_network('10.1.0.0/16') ),
            ])
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)
        a = FS_nlri(components=[
            FS_component(component_type=IP_SOURCE, op_value=ipaddress.ip_network('10.0.0.0/8') ),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=IP_SOURCE, op_value=ipaddress.ip_network('10.1.0.0/16') ),
            ])
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)

    def test_ip_prefix_different_common(self):
        a = FS_nlri(components=[
            FS_component(component_type=IP_DESTINATION, op_value=ipaddress.ip_network('10.0.0.0/8') ),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=IP_DESTINATION, op_value=ipaddress.ip_network('11.1.0.0/16') ),
            ])
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)
        a = FS_nlri(components=[
            FS_component(component_type=IP_SOURCE, op_value=ipaddress.ip_network('10.0.0.0/8') ),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=IP_SOURCE, op_value=ipaddress.ip_network('11.1.0.0/16') ),
            ])
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)

    def test_other_component_memcmp(self):
        a = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,7])),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6])),
            ])
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)

    def test_other_component_same_common(self):
        a = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6,7])),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6])),
            ])
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)

    def test_other_component_different_common(self):
        a = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6,7])),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,3,6])),
            ])
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)
        a = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,5,6,7])),
            ])
        b = FS_nlri(components=[
            FS_component(component_type=4, op_value=bytearray([0,1,2,3,4,6,6])),
            ])
        self.assertEqual(flow_rule_cmp(a, b), A_HAS_PRECEDENCE)
        a, b = b, a
        self.assertEqual(flow_rule_cmp(a, b), B_HAS_PRECEDENCE)


if __name__ == '__main__':
    unittest.main()
