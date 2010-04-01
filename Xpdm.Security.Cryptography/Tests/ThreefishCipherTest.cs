using Xpdm.Security.Cryptography;
using NUnit.Framework;

namespace Xpdm.Security.Cryptography.Tests
{
	public abstract class ThreefishCipherTest
	{
		internal TCipher PrepareObjectUnderTest<TCipher>(ulong[] key, ulong[] tweak) where TCipher : ThreefishCipher, new()
		{
			var cipher = new TCipher();
			cipher.SetKey(key);
			cipher.SetTweak(tweak);
			return cipher;
		}
	}
}
