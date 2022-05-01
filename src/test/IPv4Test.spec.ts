/*
   Copyright 2022 Nikita Petko <petko@vmminfra.net>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*
    File Name: IPv4Test.spec.ts
    Description: IPv4 test specification
    Written by: Nikita Petko
*/

import net from '..';

describe('IPv4', () => {
  // Checking the validity of the IPv4 address
  describe('#isIPv4', () => {
    it('should return true for a valid IPv4 address', () => {
      expect(net.isIPv4('127.0.0.1')).toBe(true);
      expect(net.isIPv4('::1')).toBe(false);
      expect(net.isIPv4('10.0.0.1')).toBe(true);
    });

    // While it is technically a valid IP address,
    // the IsIPv4 function will check if it's
    // human-readable IP not an number.
    it('should return false for number ip', () => {
      expect(net.isIPv4(0x7f000001 as any)).toBe(false);
    });

    it('should return false for invalid ipv4', () => {
      expect(net.isIPv4('foo')).toBe(false);
      expect(net.isIPv4('::1')).toBe(false);
    });
  });

  // Converting the IPv4 address to a number
  describe('#ipv4ToNumber', () => {
    it('should convert any valid IPv4 to a number between 0 and 4294967295', () => {
      expect(net.ipv4ToNumber('127.0.0.1')).toBe(0x7f000001);
      expect(net.ipv4ToNumber('::1')).toBe(0);
      expect(net.ipv4ToNumber('10.0.0.1')).toBe(0x0a000001);
    });

    it('should return 0 for invalid ipv4', () => {
      expect(net.ipv4ToNumber('foo')).toBe(0);
      expect(net.ipv4ToNumber('::1')).toBe(0);
    });
  });

  // Converting a number to an IPv4 address
  describe('#numberToIPv4', () => {
    it('should return the IPv4 for any number between 0 and 0xffffffff', () => {
      expect(net.numberToIPv4(0x7f000001)).toBe('127.0.0.1');
      expect(net.numberToIPv4(0x0a000001)).toBe('10.0.0.1');
    });

    it('should return 0.0.0.0 for numbers less than or equal to 0', () => {
      expect(net.numberToIPv4(0)).toBe('0.0.0.0');
      expect(net.numberToIPv4(-1)).toBe('0.0.0.0');
      expect(net.numberToIPv4(-0xffffffff)).toBe('0.0.0.0');
      expect(net.numberToIPv4(-0xfffffffffn)).toBe('0.0.0.0');
    });

    it('should return 255.255.255.255 for numbers above 0xffffffff', () => {
      expect(net.numberToIPv4(0xffffffff)).toBe('255.255.255.255');
      expect(net.numberToIPv4(0xfffffffffn)).toBe('255.255.255.255'); // bigint for 68719476735
    });

    it('should convert bigint to number and still produce the correct ip', () => {
      expect(net.numberToIPv4(0x7f000001n)).toBe('127.0.0.1');
      expect(net.numberToIPv4(0x0a000001n)).toBe('10.0.0.1');
    });
  });

  // Converting an IPv4 CIDR to it's respective start and end addresses
  describe('#ipv4CIDRToStartEnd', () => {
    it('should return the correct start and end for any valid ipv4 cidr', () => {
      expect(net.ipv4CIDRToStartEnd('127.0.0.0/32')).toStrictEqual(['127.0.0.0', '127.0.0.0']);
      expect(net.ipv4CIDRToStartEnd('10.0.0.0/8')).toStrictEqual(['10.0.0.0', '10.255.255.255']);
    });

    it('should return null if the cidr subnet is not a valid ipv4 subnet', () => {
      expect(net.ipv4CIDRToStartEnd('blah')).toStrictEqual([null, null]);
      expect(net.ipv4CIDRToStartEnd('::1')).toStrictEqual([null, null]);
    });

    it('should return null if the mask bits are invalid or out of range', () => {
      expect(net.ipv4CIDRToStartEnd('10.0.0.0/33')).toStrictEqual([null, null]);
      expect(net.ipv4CIDRToStartEnd('12.12.12.12/foo')).toStrictEqual([null, null]);
      expect(net.ipv4CIDRToStartEnd('127.0.0.0/-1')).toStrictEqual([null, null]);
    });

    it('should return the cidr subnet if the cidr subnet has no mask specified', () => {
      // It assumes /32 for the mask if none is specified
      expect(net.ipv4CIDRToStartEnd('10.0.0.0')).toStrictEqual(['10.0.0.0', '10.0.0.0']);
      expect(net.ipv4CIDRToStartEnd('108.230.222.2')).toStrictEqual(['108.230.222.2', '108.230.222.2']);
    });
  });

  // Converting an IPv4 start and end address to it's respective smallest CIDR
  describe('#ipv4StartEndToCIDR', () => {
    it('should return the correct cidr for any valid ipv4 start and end', () => {
      expect(net.ipv4StartEndToCIDR('10.0.0.0', '10.255.255.255')).toBe('10.0.0.0/8');
      expect(net.ipv4StartEndToCIDR('224.0.0.0', '239.255.255.255')).toBe('224.0.0.0/4');
    });

    it('should return null if the start or end is not a valid ipv4 address', () => {
      expect(net.ipv4StartEndToCIDR('::1', '128.0.0.0')).toBe(null);
      expect(net.ipv4StartEndToCIDR('foo', 'bar')).toBe(null);
      expect(net.ipv4StartEndToCIDR('-10', '192.65.23.33')).toBe(null);
    });

    it('should return the start/32 if the start and end are the same', () => {
      expect(net.ipv4StartEndToCIDR('10.0.0.0', '10.0.0.0')).toBe('10.0.0.0/32');
      expect(net.ipv4StartEndToCIDR('254.023.22.0', '254.023.22.0')).toBe('254.023.22.0/32');
    });
  });

  // Checking if an IPv4 address is within a range subnet (x.x.x.x-y.y.y.y)
  describe('#isIPv4InRange', () => {
    it('should return true if the ip is in the range', () => {
      // 127.0.0.0/8
      expect(net.isIPv4InRange('127.0.0.1', '127.0.0.0-127.255.255.255')).toBe(true);
      // 10.0.0.0/8
      expect(net.isIPv4InRange('10.0.0.1', '10.0.0.0-10.255.255.255')).toBe(true);
      // 172.16.0.0/12
      expect(net.isIPv4InRange('5.2.44.2', '172.16.0.0-172.31.255.255')).toBe(false);
    });

    it('should return false if ip or range is empty', () => {
      expect(net.isIPv4InRange('', '10.0.0.0-12.0.0.0')).toBe(false);
      expect(net.isIPv4InRange('10.0.0.0', '')).toBe(false);
      expect(net.isIPv4InRange('', '')).toBe(false);
    });

    it('should return true if the ip is the same as the range', () => {
      // /32
      expect(net.isIPv4InRange('10.0.0.0', '10.0.0.0')).toBe(true);
      expect(net.isIPv4InRange('172.22.22.3', '172.22.2.34')).toBe(false);
    });

    it('should transform * to 0-255', () => {
      expect(net.isIPv4InRange('10.0.0.0', '10.0.*.*')).toBe(true);
      expect(net.isIPv4InRange('127.0.0.1', '127.0.*.*')).toBe(true);
      expect(net.isIPv4InRange('172.16.0.2', '172.16.*.*')).toBe(true);
    });

    it('should return false if the ip is not a valid ipv4 address', () => {
      expect(net.isIPv4InRange('::1', '10.0.0.0-10.255.255.255')).toBe(false);
      expect(net.isIPv4InRange('foo', '127.0.0.0-127.255.255.255')).toBe(false);
    });

    it('should return false if the range lower or upper bound is not a valid ipv4 address', () => {
      expect(net.isIPv4InRange('10.0.0.1', 'foo-10.255.255.255')).toBe(false);
      expect(net.isIPv4InRange('127.0.0.1', '127.0.0.1-bar')).toBe(false);
    });
  });

  // Checking if an IPv4 address is within any of a list of ranges (x.x.x.x-y.y.y.y)
  describe('#isIPv4InRangeList', () => {
    it('should return true if the ip is in any of the ranges', () => {
      // 127.0.0.0/8 and 192.168.0.0/16
      expect(net.isIPv4InRangeList('127.0.0.1', ['127.0.0.0-127.255.255.255', '192.168.0.0-192.168.255.255'])).toBe(
        true,
      );
      // 10.0.0.0/8 and 224.0.0.0/4
      expect(net.isIPv4InRangeList('224.3.200.3', ['10.0.0.0-10.255.255.255', '224.0.0.0-239.255.255.255'])).toBe(true);
      // 172.16.0.0/12 and 5.0.0.0/8
      expect(net.isIPv4InRangeList('108.203.221.11', ['172.16.0.0-172.31.255.255', '5.0.0.0-5.255.255.255'])).toBe(
        false,
      );
    });

    it('should return false if ranges is an empty array', () => {
      expect(net.isIPv4InRangeList('10.0.0.1', [])).toBe(false);
      expect(net.isIPv4InRangeList('', [])).toBe(false);
    });

    it('should return false if ip is not a valid ipv4 address', () => {
      expect(net.isIPv4InRangeList('::1', ['10.0.0.0-10.255.255.255'])).toBe(false);
      expect(net.isIPv4InRangeList('foo', ['127.0.0.0-127.255.255.255'])).toBe(false);
    });
  });

  // Checking if an IPv4 address is within a netmask range (x.x.x.x/y.y.y.y)
  describe('#isIPv4InNetmask', () => {
    it('should return true if the ip is in the range', () => {
      // 10.0.0.0/8
      expect(net.isIPv4InNetmask('10.0.0.1', '10.0.0.0/255.0.0.0')).toBe(true);
      // 192.168.0.0/16
      expect(net.isIPv4InNetmask('192.168.0.50', '192.168.0.0/255.255.0.0')).toBe(true);
      // 172.16.0.0/12
      expect(net.isIPv4InNetmask('127.0.0.1', '172.16.0.0/255.248.0.0')).toBe(false);
    });

    it('should return false if ip or netmask is empty', () => {
      expect(net.isIPv4InNetmask('', '10.0.0.0/255.0.0.0')).toBe(false);
      expect(net.isIPv4InNetmask('127.0.0.1', '')).toBe(false);
      expect(net.isIPv4InNetmask('', '')).toBe(false);
    });

    it('should return true if the ip is the same as the netmask', () => {
      // /32
      expect(net.isIPv4InNetmask('10.0.0.1', '10.0.0.1')).toBe(true);
    });

    it('should return true if the netmask is 0.0.0.0/0.0.0.0', () => {
      // /0
      expect(net.isIPv4InNetmask('10.0.0.1', '0.0.0.0/0.0.0.0')).toBe(true);
    });

    it("should set the mask to 32 bits if it's not a valid ipv4", () => {
      expect(net.isIPv4InNetmask('10.0.0.1', '10.0.0.1/foo')).toBe(true);
      expect(net.isIPv4InNetmask('127.0.0.1', '127.0.0.1/::')).toBe(true);
      expect(net.isIPv4InNetmask('172.16.0.1', '10.0.0.1/foo')).toBe(false);
    });

    it('should return false if the ip is not a valid ipv4 address', () => {
      expect(net.isIPv4InNetmask('::1', '10.0.0.0/255.0.0.0')).toBe(false);
      expect(net.isIPv4InNetmask('foo', '192.168.0.0/255.255.0.0')).toBe(false);
    });

    it('should return false if the netmask is not a valid ipv4 address', () => {
      expect(net.isIPv4InNetmask('10.0.0.0', 'foo/255.255.255.0')).toBe(false);
    });

    it('should return false if the netmask subnet mask is not a valid ipv4 address', () => {
      expect(net.isIPv4InNetmask('10.0.0.1', '10.0.0.0/foo')).toBe(false);
    });
  });

  // Checking if an IPv4 address is within any of a list of netmasks (x.x.x.x/y.y.y.y)
  describe('#isIPv4InNetmaskList', () => {
    it('should return true if the ip is in any of the ranges', () => {
      // 10.0.0.0/8 and 192.168.0.0/16
      expect(net.isIPv4InNetmaskList('10.0.0.1', ['10.0.0.0/255.0.0.0', '192.168.0.0/255.255.0.0'])).toBe(true);
      // 127.0.0.0/8 and 224.0.0.0/4
      expect(net.isIPv4InNetmaskList('224.3.230.10', ['127.0.0.1/255.0.0.0', '224.0.0.0/240.0.0.0'])).toBe(true);
      // 172.16.0.0/12 and 5.0.0.0/8
      expect(net.isIPv4InNetmaskList('102.30.203.11', ['172.16.0.0/255.254.0.0', '5.0.0.0/8'])).toBe(false);
    });

    it('should return false if ranges is an empty array', () => {
      expect(net.isIPv4InNetmaskList('10.0.0.1', [])).toBe(false);
      expect(net.isIPv4InNetmaskList('', [])).toBe(false);
    });

    it('should return false if ip is not a valid ipv4 address', () => {
      expect(net.isIPv4InNetmaskList('::1', ['10.0.0.0/255.0.0.0'])).toBe(false);
      expect(net.isIPv4InNetmaskList('foo', ['127.0.0.0/255.0.0.0'])).toBe(false);
    });
  });

  // Checking if an IPv4 address is within a CIDR range (x.x.x.x/y)
  describe('#isIPv4InCidrRange', () => {
    it('should return true if the ip is in the range', () => {
      // 127.0.0.0/8
      expect(net.isIPv4InCidrRange('127.0.0.1', '127.0.0.0/8')).toBe(true);
      // 172.16.0.0/12
      expect(net.isIPv4InCidrRange('172.17.30.33', '172.16.0.0/12')).toBe(true);
      // 224.0.0.0/4
      expect(net.isIPv4InCidrRange('10.0.0.1', '224.0.0.0/4')).toBe(false);
    });

    it('should return false if ip or cidr is empty', () => {
      expect(net.isIPv4InCidrRange('', '10.0.0.0/8')).toBe(false);
      expect(net.isIPv4InCidrRange('127.0.0.1', '')).toBe(false);
      expect(net.isIPv4InCidrRange('', '')).toBe(false);
    });

    it('should return true if the ip is the same as the cidr', () => {
      // /32
      expect(net.isIPv4InCidrRange('10.0.0.0', '10.0.0.0/32')).toBe(true);
      expect(net.isIPv4InCidrRange('127.0.0.0', '127.0.0.0')).toBe(true);
    });

    it('should return true if the cidr is 0.0.0.0/0', () => {
      // /0
      expect(net.isIPv4InCidrRange('127.0.0.1', '0.0.0.0/0')).toBe(true);
    });

    it('should set the mask to 32 bits if it is not set', () => {
      expect(net.isIPv4InCidrRange('10.0.0.0', '10.0.0.0')).toBe(true);
      expect(net.isIPv4InCidrRange('127.0.0.1', '127.0.0.1')).toBe(true);
      expect(net.isIPv4InCidrRange('172.16.0.10', '10.0.0.0')).toBe(false);
    });

    it('should return false if the ip is not a valid ipv4 address', () => {
      expect(net.isIPv4InCidrRange('::1', '127.0.0.0/8')).toBe(false);
      expect(net.isIPv4InCidrRange('foo', '10.0.0.0/8')).toBe(false);
    });

    it('should set the mask to 32 if the mask was not specified or was out of range', () => {
      expect(net.isIPv4InCidrRange('10.0.0.1', '10.0.0.1')).toBe(true); // the first check will catch this
      expect(net.isIPv4InCidrRange('10.0.0.0', '10.0.0.0/foo')).toBe(true);
      expect(net.isIPv4InCidrRange('10.0.0.0', '10.0.0.0/33')).toBe(true);
      expect(net.isIPv4InCidrRange('10.0.0.0', '10.0.0.0/-1')).toBe(true);
    });
  });

  // Checking if an IPv4 address is within a list of CIDR ranges (x.x.x.x/y)
  describe('#isIPv4InCidrRangeList', () => {
    it('should return true if the ip is in any of the ranges', () => {
      // 10.0.0.0/8 and 192.168.0.0/16
      expect(net.isIPv4InCidrRangeList('10.0.0.1', ['10.0.0.0/8', '192.168.0.0/16'])).toBe(true);
      // 224.0.0.0/4 and 172.16.0.0/12
      expect(net.isIPv4InCidrRangeList('172.30.11.30', ['224.0.0.0/4', '172.16.0.0/12'])).toBe(true);
      // 11.0.0.0/8 and 127.0.0.0/8
      expect(net.isIPv4InCidrRangeList('203.0.0.20', ['11.0.0.0/8', '127.0.0.0/8'])).toBe(false);
    });

    it('should return false if ranges is an empty array', () => {
      expect(net.isIPv4InCidrRangeList('10.0.0.1', [])).toBe(false);
      expect(net.isIPv4InCidrRangeList('', [])).toBe(false);
    });

    it('should return false if ip is not a valid ipv4 address', () => {
      expect(net.isIPv4InCidrRangeList('::1', ['10.0.0.0/8'])).toBe(false);
      expect(net.isIPv4InCidrRangeList('foo', ['127.0.0.0/8'])).toBe(false);
    });
  });

  // Checking if an IPv4 address is within a CIDR, netmask or Range (x.x.x.x/y, x.x.x.x/y.y.y.y or x.x.x.x-x.x.x.x)
  describe('#isIPv4InCidrNetmaskOrRange', () => {
    it('should return true if the ip is in the range', () => {
      // 10.0.0.0/8 and 127.0.0.0/8
      expect(net.isIPv4InCidrNetmaskOrRange('127.0.0.1', '127.0.0.0/8')).toBe(true);
      expect(net.isIPv4InCidrNetmaskOrRange('10.0.0.1', '10.0.0.0/255.0.0.0')).toBe(true);
      expect(net.isIPv4InCidrNetmaskOrRange('127.0.0.1', '10.0.0.0-10.255.255.255')).toBe(false);
    });

    it('should return false if ip or cidr is empty', () => {
      expect(net.isIPv4InCidrNetmaskOrRange('', '10.0.0.0/8')).toBe(false);
      expect(net.isIPv4InCidrNetmaskOrRange('127.0.0.1', '')).toBe(false);
      expect(net.isIPv4InCidrNetmaskOrRange('', '')).toBe(false);
    });

    it('should return true if the ip is the same as the cidr', () => {
      // /32
      expect(net.isIPv4InCidrNetmaskOrRange('10.0.0.1', '10.0.0.1/32')).toBe(true);
      expect(net.isIPv4InCidrNetmaskOrRange('10.0.0.1', '10.0.0.1')).toBe(true);
    });

    it('should return false if the ip is not a valid ipv4 address', () => {
      expect(net.isIPv4InCidrNetmaskOrRange('::1', '10.0.0.0/8')).toBe(false);
      expect(net.isIPv4InCidrNetmaskOrRange('foo', '127.0.0.0/8')).toBe(false);
    });
  });

  // Checking if an IPv4 address is within a list of CIDR, netmask or Range (x.x.x.x/y, x.x.x.x/y.y.y.y or x.x.x.x-x.x.x.x)
  describe('#isIPv4InCidrNetmaskOrRangeList', () => {
    it('should return true if the ip is in any of the ranges', () => {
      // 10.0.0.0/8 and 127.0.0.0/8
      expect(net.isIPv4InCidrNetmaskOrRangeList('127.0.0.1', ['10.0.0.0/8', '127.0.0.0/255.0.0.0'])).toBe(true);
      expect(net.isIPv4InCidrNetmaskOrRangeList('10.0.0.1', ['127.0.0.0/255.0.0.0', '10.0.0.0-10.255.255.255'])).toBe(
        true,
      );
      expect(net.isIPv4InCidrNetmaskOrRangeList('172.16.0.10', ['10.0.0.0/8', '127.0.0.0/8'])).toBe(false);
    });

    it('should return false if ranges is an empty array', () => {
      expect(net.isIPv4InCidrNetmaskOrRangeList('10.0.0.1', [])).toBe(false);
      expect(net.isIPv4InCidrNetmaskOrRangeList('', [])).toBe(false);
    });

    it('should return false if ip is not a valid ipv4 address', () => {
      expect(net.isIPv4InCidrNetmaskOrRangeList('::1', ['10.0.0.0/8'])).toBe(false);
      expect(net.isIPv4InCidrNetmaskOrRangeList('foo', ['127.0.0.0/8'])).toBe(false);
    });
  });

  // Checking if IP is RFC1918
  describe('#isIPv4RFC1918', () => {
    it('should return true if the ip is RFC1918', () => {
      expect(net.isIPv4RFC1918('10.0.0.1')).toBe(true);
      expect(net.isIPv4RFC1918('192.168.0.1')).toBe(true);
      expect(net.isIPv4RFC1918('172.16.0.1')).toBe(true);
      expect(net.isIPv4RFC1918('5.0.0.1')).toBe(false);
    });
  });

  // Checking if IP is loopback
  describe('#isIPv4Loopback', () => {
    it('should return true if the ip is loopback', () => {
      expect(net.isIPv4Loopback('127.0.0.1')).toBe(true);
      expect(net.isIPv4Loopback('10.0.0.1')).toBe(false);
    });
  });

  // Checking if IP is link-local
  describe('#isIPv4LinkLocal', () => {
    it('should return true if the ip is link-local', () => {
      expect(net.isIPv4LinkLocal('169.254.0.1')).toBe(true);
      expect(net.isIPv4LinkLocal('10.0.0.1')).toBe(false);
    });
  });

  // Checking if a CIDR is a valid IPv4 CIDR
  describe('#isCidrIPv4', () => {
    it('should return true if the cidr is a valid IPv4 CIDR', () => {
      expect(net.isCidrIPv4('10.0.0.0/8')).toBe(true);
      expect(net.isCidrIPv4('::1/128')).toBe(false);
    });
  });
});
