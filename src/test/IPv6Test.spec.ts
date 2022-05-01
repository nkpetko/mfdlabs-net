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
    File Name: IPv6Test.spec.ts
    Description: IPv6 test cases
    Written by: Nikita Petko
*/

import net from '..';

function serializeBigInt(bigInt: bigint | number): string {
  return bigInt.toString();
}

describe('IPv6', () => {
  // Decompressing an IPv6 address
  describe('#decompressIPv6', () => {
    it('should decompress an IPv6 address', () => {
      expect(net.decompressIPv6('2001:db8:85a3::8a2e:370:7334')).toBe('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      expect(net.decompressIPv6('::1')).toBe('0000:0000:0000:0000:0000:0000:0000:0001');
      expect(net.decompressIPv6('::')).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
    });

    it('should decompress IPv4 mapped IPv6 address', () => {
      expect(net.decompressIPv6('::ffff:127.0.0.1')).toBe('0000:0000:0000:0000:0000:ffff:7f00:0001');
      expect(net.decompressIPv6('::ffff:192.168.0.50')).toBe('0000:0000:0000:0000:0000:ffff:c0a8:0032');
      expect(net.decompressIPv6('127.0.0.1')).toBe('0000:0000:0000:0000:0000:ffff:7f00:0001');
      expect(net.decompressIPv6('192.168.0.50')).toBe('0000:0000:0000:0000:0000:ffff:c0a8:0032');
    });

    it('should return the input if it is not a valid IPv6 address', () => {
      expect(net.decompressIPv6('foo')).toBe('foo');
      expect(net.decompressIPv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334:')).toBe(
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334:',
      );
    });
  });

  // Compressing an IPv6 address
  describe('#compressIPv6', () => {
    it('should compress an IPv6 address', () => {
      expect(net.compressIPv6('2001:db8:85a3:0000:0000:8a2e:370:7334')).toBe('2001:db8:85a3::8a2e:370:7334');
      expect(net.compressIPv6('0000:0000:0000:0000:0000:0000:0000:0001')).toBe('::1');
      expect(net.compressIPv6('0000:0000:0000:0000:0000:0000:0000:0000')).toBe('::');
    });

    it('should return the input if it is not a valid IPv6 address', () => {
      expect(net.compressIPv6('foo')).toBe('foo');
      expect(net.compressIPv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334:')).toBe('2001:0db8:85a3:0000:0000:8a2e:0370:7334:');
      expect(net.compressIPv6('127.0.0.1')).toBe('127.0.0.1');
    });
  });

  // Checking the validity of the IPv6 address
  describe('#isIPv6', () => {
    it('should return true for a valid IPv6 address', () => {
      expect(net.isIPv6('::1')).toBe(true);
      expect(net.isIPv6('127.0.0.1')).toBe(false);
      expect(net.isIPv6('fe80::1')).toBe(true);
    });

    // While it is technically a valid IP address,
    // the IsIPv6 function will check if it's
    // human-readable IP not an number.
    it('should return false for number ip', () => {
      expect(net.isIPv6(0x7f000001 as any)).toBe(false);
    });

    it('should return false for invalid ipv6', () => {
      expect(net.isIPv6('foo')).toBe(false);
      expect(net.isIPv6('127.0.0.1')).toBe(false);
    });
  });

  /* Commented out because Jest cannot serialize BigInt
   * A fix for this would be to fetch SMALL numbers and convert them to Number
   * before passing them to the expect function
   *
   * More info: It was never because of Jest, it's because JSON.stringify does not recognize BigInt
   *
   * 15/04/2022: Fixed by .toString()
   */
  // Converting the IPv6 address to a number
  describe('#ipv6ToNumber', () => {
    it('should convert any valid IPv6 to a number between 0 and 4294967295', () => {
      expect(net.ipv6ToNumber('::1').toString()).toBe(serializeBigInt(0x1));
      expect(net.ipv6ToNumber('127.0.0.1').toString()).toBe(serializeBigInt(0));
      expect(net.ipv6ToNumber('fe80::1').toString()).toBe(serializeBigInt(0xfe800000000000000000000000000001n));
    });

    it('should return 0 for invalid ipv6', () => {
      expect(net.ipv6ToNumber('foo').toString()).toBe(serializeBigInt(0));
      expect(net.ipv6ToNumber('127.0.0.1').toString()).toBe(serializeBigInt(0));
    });
  });

  // Converting a number to an IPv6 address
  describe('#numberToIPv6', () => {
    it('should return the IPv6 for any number between 0n and 0xffffffffffffffffffffffffffffffffn', () => {
      expect(net.numberToIPv6(0x7f000001)).toBe('::7f00:1');
      expect(net.numberToIPv6(0x1)).toBe('::1');
      expect(net.numberToIPv6(0xfe800000000000000000000000000001n)).toBe('fe80::1');
      expect(net.numberToIPv6(0xffffffffffffffffffffffffffffffffn)).toBe('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
      expect(net.numberToIPv6(0x7f000001, false)).toBe('0000:0000:0000:0000:0000:0000:7f00:0001');
      expect(net.numberToIPv6(0x1, false)).toBe('0000:0000:0000:0000:0000:0000:0000:0001');
      expect(net.numberToIPv6(0xfe800000000000000000000000000001n, false)).toBe(
        'fe80:0000:0000:0000:0000:0000:0000:0001',
      );
      expect(net.numberToIPv6(0xffffffffffffffffffffffffffffffffn, false)).toBe(
        'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      );
    });

    it('should return 0000:0000:0000:0000:0000:0000:0000:0000 or :: for numbers below 0n', () => {
      expect(net.numberToIPv6(0)).toBe('::');
      expect(net.numberToIPv6(-1)).toBe('::');
      expect(net.numberToIPv6(-0xffffffff)).toBe('::');
      expect(net.numberToIPv6(-0xfffffffffn)).toBe('::');
      expect(net.numberToIPv6(0, false)).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
      expect(net.numberToIPv6(-1, false)).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
      expect(net.numberToIPv6(-0xffffffff, false)).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
      expect(net.numberToIPv6(-0xfffffffffn, false)).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
    });

    it('should return ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff for numbers above 0xffffffffffffffffffffffffffffffffn', () => {
      expect(net.numberToIPv6(0xffffffffffffffffffffffffffffffffn)).toBe('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
      expect(net.numberToIPv6(0xfffffffffffffffffffffffffffffffffn)).toBe('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
    });

    it('should convert bigint to number and still produce the correct ip', () => {
      expect(net.numberToIPv6(0x7f000001n)).toBe('::7f00:1');
      expect(net.numberToIPv6(0x0a000001n)).toBe('::a00:1');
      expect(net.numberToIPv6(0xfe800000000000000000000000000001n)).toBe('fe80::1');
      expect(net.numberToIPv6(0xffffffffffffffffffffffffffffffffn)).toBe('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
      expect(net.numberToIPv6(0x7f000001n, false)).toBe('0000:0000:0000:0000:0000:0000:7f00:0001');
      expect(net.numberToIPv6(0x0a000001n, false)).toBe('0000:0000:0000:0000:0000:0000:0a00:0001');
      expect(net.numberToIPv6(0xfe800000000000000000000000000001n, false)).toBe(
        'fe80:0000:0000:0000:0000:0000:0000:0001',
      );
      expect(net.numberToIPv6(0xffffffffffffffffffffffffffffffffn, false)).toBe(
        'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      );
    });
  });

  // Converting an IPv6 CIDR to it's respective start and end addresses
  describe('#ipv6CIDRToStartEnd', () => {
    it('should return the correct start and end for any valid ipv6 cidr', () => {
      expect(net.ipv6CIDRToStartEnd('::1/128')).toEqual(['::1', '::1']);
      expect(net.ipv6CIDRToStartEnd('fd0::/8')).toEqual(['f00::', 'fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']);
      expect(net.ipv6CIDRToStartEnd('::1/128', false)).toEqual([
        '0000:0000:0000:0000:0000:0000:0000:0001',
        '0000:0000:0000:0000:0000:0000:0000:0001',
      ]);
      expect(net.ipv6CIDRToStartEnd('fd0::/8', false)).toEqual([
        '0f00:0000:0000:0000:0000:0000:0000:0000',
        '0fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      ]);
    });

    it('should return null if the cidr subnet is not a valid ipv6 subnet', () => {
      expect(net.ipv6CIDRToStartEnd('blah')).toStrictEqual([null, null]);
      expect(net.ipv6CIDRToStartEnd('127.0.0.1/8')).toStrictEqual([null, null]);
    });

    it('should return null if the mask bits are invalid or out of range', () => {
      expect(net.ipv4CIDRToStartEnd('::1/129')).toStrictEqual([null, null]);
      expect(net.ipv4CIDRToStartEnd('fd0::/foo')).toStrictEqual([null, null]);
      expect(net.ipv4CIDRToStartEnd('::/-1')).toStrictEqual([null, null]);
    });

    it('should return the cidr subnet if the cidr subnet has no mask specified', () => {
      // It assumes /32 for the mask if none is specified
      expect(net.ipv6CIDRToStartEnd('::1')).toEqual(['::1', '::1']);
      expect(net.ipv6CIDRToStartEnd('fd0::')).toEqual(['fd0::', 'fd0::']);
      expect(net.ipv6CIDRToStartEnd('::1', false)).toEqual([
        '0000:0000:0000:0000:0000:0000:0000:0001',
        '0000:0000:0000:0000:0000:0000:0000:0001',
      ]);
      expect(net.ipv6CIDRToStartEnd('fd0::', false)).toEqual([
        '0fd0:0000:0000:0000:0000:0000:0000:0000',
        '0fd0:0000:0000:0000:0000:0000:0000:0000',
      ]);
    });
  });

  // Converting an IPv6 start and end address to it's respective smallest CIDR
  describe('#ipv6StartEndToCIDR', () => {
    it('should return the correct cidr for any valid ipv6 start and end', () => {
      expect(net.ipv6StartEndToCIDR('::1', '::1')).toBe('::1/128');
      expect(net.ipv6StartEndToCIDR('0f00::', '0fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).toBe('f00::/8');
      expect(net.ipv6StartEndToCIDR('::1', '::1', false)).toBe('0000:0000:0000:0000:0000:0000:0000:0001/128');
      expect(net.ipv6StartEndToCIDR('fd0::', '0fd0:ffff:ffff:ffff:ffff:ffff:ffff:ffff', false)).toBe(
        '0fd0:0000:0000:0000:0000:0000:0000:0000/16',
      );
    });

    it('should return null if the start or end is not a valid ipv6 address', () => {
      expect(net.ipv6StartEndToCIDR('::1', '128.0.0.0')).toBe(null);
      expect(net.ipv6StartEndToCIDR('foo', 'bar')).toBe(null);
      expect(net.ipv6StartEndToCIDR('-10', '192.65.23.33')).toBe(null);
    });

    it('should return the start/128 if the start and end are the same', () => {
      expect(net.ipv6StartEndToCIDR('::1', '::1')).toBe('::1/128');
      expect(net.ipv6StartEndToCIDR('fd0::', 'fd0::')).toBe('fd0::/128');
      expect(net.ipv6StartEndToCIDR('::1', '::1', false)).toBe('0000:0000:0000:0000:0000:0000:0000:0001/128');
      expect(net.ipv6StartEndToCIDR('fd0::', 'fd0::', false)).toBe('0fd0:0000:0000:0000:0000:0000:0000:0000/128');
    });
  });

  // Checking if an IPv6 address is within a range subnet (x.x.x.x-y.y.y.y)
  describe('#isIPv6InRange', () => {
    it('should return true if the ip is in the range', () => {
      // 127.0.0.0/8
      expect(net.isIPv6InRange('::1', '::1-::1')).toBe(true);
      // 10.0.0.0/8
      expect(net.isIPv6InRange('::1', '::1-::ffff:ffff:ffff:ffff')).toBe(true);
      // 172.16.0.0/12
      expect(net.isIPv6InRange('::1', '::ffff:ffff:ffff:ffff-::ffff:ffff:ffff:ffff')).toBe(false);
    });

    it('should return false if ip or range is empty', () => {
      expect(net.isIPv6InRange('', '::1-::1')).toBe(false);
      expect(net.isIPv6InRange('::1', '')).toBe(false);
      expect(net.isIPv6InRange('', '')).toBe(false);
    });

    it('should return true if the ip is the same as the range', () => {
      // /128
      expect(net.isIPv6InRange('::1', '::1')).toBe(true);
      expect(net.isIPv6InRange('ffdc::', 'fdc0::')).toBe(false);
    });

    it('should return false if the ip is not a valid ipv6 address', () => {
      expect(net.isIPv6InRange('::1', '10.0.0.0-10.255.255.255')).toBe(false);
      expect(net.isIPv6InRange('foo', '127.0.0.0-127.255.255.255')).toBe(false);
    });

    it('should return false if the range lower or upper bound is not a valid ipv6 address', () => {
      expect(net.isIPv6InRange('10.0.0.1', 'foo-10.255.255.255')).toBe(false);
      expect(net.isIPv6InRange('127.0.0.1', '127.0.0.1-bar')).toBe(false);
    });
  });

  // Checking if an IPv6 address is within any of a list of ranges (x.x.x.x-y.y.y.y)
  describe('#isIPv6InRangeList', () => {
    it('should return true if the ip is in any of the ranges', () => {
      // ::1/128 and fdc0::/8
      expect(net.isIPv6InRangeList('::1', ['::1-::1', 'fdc0::-fdc0::'])).toBe(true);
      // ::1/128 and ::ffff:ffff:ffff:ffff/128
      expect(net.isIPv6InRangeList('::1', ['::1-::1', '::ffff:ffff:ffff:ffff-::ffff:ffff:ffff:ffff'])).toBe(true);
      // fccf::/8 and ::ffff:ffff:ffff:ffff/128
      expect(
        net.isIPv6InRangeList('::1', [
          'fc00::-fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
          '::ffff:ffff:ffff:ffff-::ffff:ffff:ffff:ffff',
        ]),
      ).toBe(false);
    });

    it('should return false if ranges is an empty array', () => {
      expect(net.isIPv6InRangeList('::1', [])).toBe(false);
      expect(net.isIPv6InRangeList('', [])).toBe(false);
    });

    it('should return false if ip is not a valid ipv6 address', () => {
      expect(net.isIPv6InRangeList('127.0.0.1', ['::1-::1', '::ffff:ffff:ffff:ffff-::ffff:ffff:ffff:ffff'])).toBe(
        false,
      );
      expect(net.isIPv6InRangeList('foo', ['::1-::1', '::ffff:ffff:ffff:ffff-::ffff:ffff:ffff:ffff'])).toBe(false);
    });
  });

  // Checking if an IPv6 address is within a CIDR range (x.x.x.x/y)
  describe('#isIPv6InCidrRange', () => {
    it('should return true if the ip is in the range', () => {
      // ::1/128
      expect(net.isIPv6InCidrRange('::1', '::1/128')).toBe(true);
      // fdc0::/8
      expect(net.isIPv6InCidrRange('fdc0:18fd:dc0:18fd:dc0:18fd:dc0:18fd', 'fdc0::/8')).toBe(true);
      // c::ffff:ffff:ffff:ffff/4
      expect(net.isIPv6InCidrRange('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'c::ffff:ffff:ffff:ffff/4')).toBe(false);
    });

    it('should return false if ip or cidr is empty', () => {
      expect(net.isIPv6InCidrRange('', '::1/128')).toBe(false);
      expect(net.isIPv6InCidrRange('::', '')).toBe(false);
      expect(net.isIPv6InCidrRange('', '')).toBe(false);
    });

    it('should return true if the ip is the same as the cidr', () => {
      // /128
      expect(net.isIPv6InCidrRange('::1', '::1/128')).toBe(true);
      expect(net.isIPv6InCidrRange('::1', '::1')).toBe(true);
    });

    it('should return true if the cidr is ::/0', () => {
      expect(net.isIPv6InCidrRange('::1', '::/0')).toBe(true);
      expect(net.isIPv6InCidrRange('fd0c', '::/0')).toBe(true);
    });

    it("should return false if the subnet is not a valid ipv6", () => {
      expect(net.isIPv6InCidrRange('::1', '10.0.0.0/8')).toBe(false);
      expect(net.isIPv6InCidrRange('foo', 'foo/8')).toBe(false);
    });

    it('should set the mask bits to 128 if the mask was not specified', () => {
      expect(net.isIPv6InCidrRange('::1', '::1')).toBe(true);
      expect(net.isIPv6InCidrRange('::1', '::1/')).toBe(true);
      expect(net.isIPv6InCidrRange('::1', 'fdc0::/')).toBe(false);
    });

    it('should return false if the ip is not a valid ipv6 address', () => {
      expect(net.isIPv6InCidrRange('127.0.0.1', '::1/128')).toBe(false);
      expect(net.isIPv6InCidrRange('foo', 'fdc0::/8')).toBe(false);
    });

    it('should set the mask to 128 if the mask was not specified or was out of range', () => {
      expect(net.isIPv6InCidrRange('::1', '::1')).toBe(true); // /128
      expect(net.isIPv6InCidrRange('::1', '::1/foo')).toBe(true); // /128
      expect(net.isIPv6InCidrRange('::1', '::1/129')).toBe(true); // /128
      expect(net.isIPv6InCidrRange('::1', '::1/-1')).toBe(true); // /128
    });
  });

  // Checking if an IPv6 address is within a list of CIDR ranges (x.x.x.x/y)
  describe('#isIPv6InCidrRangeList', () => {
    it('should return true if the ip is in any of the ranges', () => {
      // ::1/128 and fdc0::/8
      expect(net.isIPv6InCidrRangeList('::1', ['::1/128', 'fdc0::/8'])).toBe(true);
      // ::1/128 and ::ffff:ffff:ffff:ffff/128
      expect(net.isIPv6InCidrRangeList('::1', ['::1/128', '::ffff:ffff:ffff:ffff/128'])).toBe(true);
      // fccf::/8 and ::ffff:ffff:ffff:ffff/128
      expect(net.isIPv6InCidrRangeList('::1', ['fccf::/8', '::ffff:ffff:ffff:ffff/128'])).toBe(false);
    });

    it('should return false if ranges is an empty array', () => {
      expect(net.isIPv6InCidrRangeList('::', [])).toBe(false);
      expect(net.isIPv6InCidrRangeList('', [])).toBe(false);
    });

    it('should return false if ip is not a valid ipv6 address', () => {
      expect(net.isIPv6InCidrRangeList('127.0.0.1', ['::1/8'])).toBe(false);
      expect(net.isIPv6InCidrRangeList('foo', ['::/8'])).toBe(false);
    });
  });

  // Checking if an IPv6 address is within a range (x.x.x.x-y) or cidr (x.x.x.x/y)
  describe('#isIPv6InCidrOrRange', () => {
    it('should return false if the ip or range is empty', () => {
      expect(net.isIPv6InCidrOrRange('', '::1-::1')).toBe(false);
      expect(net.isIPv6InCidrOrRange('::', '')).toBe(false);
      expect(net.isIPv6InCidrOrRange('', '')).toBe(false);
    });

    it('should return true if the ip is equal to the range', () => {
      expect(net.isIPv6InCidrOrRange('::1', '::1')).toBe(true);
      expect(net.isIPv6InCidrOrRange('fdc0::', 'fdc0::')).toBe(true);
    });

    it('should return false if the ip is not a valid ipv6 address', () => {
      expect(net.isIPv6InCidrOrRange('foo', '::1-::1')).toBe(false);
      expect(net.isIPv6InCidrOrRange('10.0.0.1', '::1-::1')).toBe(false);
    });

    it('should return true if the ip is in the range', () => {
      expect(net.isIPv6InCidrOrRange('::1', '::1-::2')).toBe(true);
      expect(net.isIPv6InCidrOrRange('::1', '::1/128')).toBe(true);
      expect(net.isIPv6InCidrOrRange('::1', '::1/8')).toBe(true);
      expect(net.isIPv6InCidrOrRange('::1', 'fdc0::/8')).toBe(false);
    });
  });

  // Checking if an IPv6 address is within a list of ranges (x.x.x.x-y) or cidrs (x.x.x.x/y)
  describe('#isIPv6InCidrOrRangeList', () => {
    it('should return false if the range list is empty', () => {
      expect(net.isIPv6InCidrOrRangeList('::', [])).toBe(false);
      expect(net.isIPv6InCidrOrRangeList('', [])).toBe(false);
    });

    it('should return false if the ip is not a valid ipv6 address', () => {
      expect(net.isIPv6InCidrOrRangeList('10.0.0.0', ['::1-::1'])).toBe(false);
      expect(net.isIPv6InCidrOrRangeList('foo', ['::1-::1'])).toBe(false);
    });

    it('should return true if the ip is in any of the ranges', () => {
      expect(net.isIPv6InCidrOrRangeList('::1', ['::1-::1', 'fdc0::/8'])).toBe(true);
      expect(net.isIPv6InCidrOrRangeList('::1', ['::1-::1', '::ffff:ffff:ffff:ffff/128'])).toBe(true);
      expect(net.isIPv6InCidrOrRangeList('::1', ['fccf::/8', '::ffff:ffff:ffff:ffff/128'])).toBe(false);
    });
  });

  // Checking if IP is RFC4193
  describe('#isIPv6RFC4193', () => {
    it('should return true if the ip is RFC1918', () => {
      expect(net.isIPv6RFC4193('fdc0:18fd:dc0:18fd:dc0:18fd:dc0:18fd')).toBe(true);
      expect(net.isIPv6RFC4193('fdc0:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).toBe(true);
      expect(net.isIPv6RFC4193('fdfd:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).toBe(true);
    });
  });

  // Checking if IP is RFC3879
  describe('#isIPv6RFC3879', () => {
    it('should return true if the ip is RFC3879', () => {
      expect(net.isIPv6RFC3879('fecc:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).toBe(true);
      expect(net.isIPv6RFC3879('fec0::')).toBe(true);
    });
  });

  // Checking if IP is loopback
  describe('#isIPv6Loopback', () => {
    it('should return true if the ip is loopback', () => {
      expect(net.isIPv6Loopback('::1')).toBe(true);
      expect(net.isIPv6Loopback('fdc0:18fd:dc0:18fd:dc0:18fd:dc0:18fd')).toBe(false);
    });
  });

  // Checking if IP is link-local
  describe('#isIPv6LinkLocal', () => {
    it('should return true if the ip is link-local', () => {
      expect(net.isIPv6LinkLocal('fe80::1')).toBe(true);
      expect(net.isIPv6LinkLocal('fdc0:18fd:dc0:18fd:dc0:18fd:dc0:18fd')).toBe(false);
    });
  });

  // Checking if a CIDR is a valid IPv6 CIDR
  describe('#isCidrIPv6', () => {
    it('should return true if the cidr is a valid IPv6 CIDR', () => {
      expect(net.isCidrIPv6('::1/128')).toBe(true);
      expect(net.isCidrIPv6('127.0.0.0/8')).toBe(false);
    });
  });
});
