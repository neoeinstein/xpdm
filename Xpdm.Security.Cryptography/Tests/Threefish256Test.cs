using System;
using NUnit.Framework;

namespace Xpdm.Security.Cryptography.Tests
{
	[TestFixture]
	public class Threefish256Test : ThreefishCipherTest
	{
		protected ulong[] key0 = new [] { 0UL, 0UL, 0UL, 0UL };
		protected ulong[] tweak0 = new [] { 0UL, 0UL };
		protected ulong[] input0 = new [] { 0UL, 0UL, 0UL, 0UL };
		protected ulong[] output0_0_0 = new [] { 0x3FCFB6F3F95697E3UL, 0x61CE24D3C32B1DF9UL, 0x7F36B22316EA7485UL, 0x58A8AF932A2E3888UL };
		protected ulong[] key1 = new [] { 0x01234567890ABCDEFUL, 0x02468ACE13579BDFUL, 0xFEDCBA9876543210UL, 0xA5A5A5A5A5A5A5A5UL };
		protected ulong[] tweak1 = new [] { 0xAAAAAAAAAAAAAAAAUL, 0x5555555555555555UL };
		protected ulong[] input1 = new [] { 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL };
		protected ulong[] output1_1_1 = new [] { 0x04B98B4773736791UL, 0x30678A4FC309171EUL, 0x5BDB38E67AD23EBFUL, 0xF40AD4DF61B91280UL };
		
		[Test]
		public void BasicAllZeroKeyTweakBlock()
		{
			var cipher = base.PrepareObjectUnderTest<Threefish256>(key0, tweak0);
			var output = new ulong[4];
			cipher.Encrypt(input0, output);
			Assert.AreEqual(output[0], output0_0_0[0]);
			Assert.AreEqual(output[1], output0_0_0[1]);
			Assert.AreEqual(output[2], output0_0_0[2]);
			Assert.AreEqual(output[3], output0_0_0[3]);
		}

		[Test]
		public void BasicAllOnesKeyTweakBlock()
		{
			var cipher = base.PrepareObjectUnderTest<Threefish256>(key1, tweak1);
			var output = new ulong[4];
			cipher.Encrypt(input1, output);
			Assert.AreEqual(output[0], output1_1_1[0]);
			Assert.AreEqual(output[1], output1_1_1[1]);
			Assert.AreEqual(output[2], output1_1_1[2]);
			Assert.AreEqual(output[3], output1_1_1[3]);
		}

		protected void PrintBlock(ulong[] block)
		{
			Console.WriteLine("{0:X16} {1:X16} {2:X16} {3:X16}", block[0], block[1], block[2], block[3]);
		}
	}
}
