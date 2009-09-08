using Mono.Simd;

namespace Xpdm.Security.Cryptography
{
	internal abstract class ThreefishCipherSimd: ThreefishCipher
	{
		protected static void Mix(ref Vector2ul a, ref Vector2ul b, int rX, int rY)
		{
			a = a + b;
			RotateLeft64(ref b, rX, rY);
			b = b ^ a;
		}
		
		protected static void RotateLeft64(ref Vector2ul val, int rX, int rY)
		{
			Vector2ul c = Vector2ul.Zero.UnpackLow(val);
			Vector2ul d = Vector2ul.Zero.UnpackHigh(val);
			c = c << rX | c >> (64 - rX);
			d = d << rY | d >> (64 - rY);
			val = c.UnpackHigh(d);
		}

		protected static void UnMix(ref Vector2ul a, ref Vector2ul b, int rX, int rY)
		{
			b = b ^ a;
			RotateRight64(ref b, rX, rY);
			a = a - b;
		}

		protected static void RotateRight64(ref Vector2ul val, int rX, int rY)
		{
			Vector2ul c = Vector2ul.Zero.UnpackLow(val);
			Vector2ul d = Vector2ul.Zero.UnpackHigh(val);
			c = c >> rX | c << (64 - rX);
			d = d >> rY | d << (64 - rY);
			val = c.UnpackHigh(d);
		}

		protected static void SubKey(ref Vector2ul val, ref Vector2ul key)
		{
			val = val + key;
		}

		protected static void UnSubKey(ref Vector2ul val, ref Vector2ul key)
		{
			val = val - key;
		}
		
		protected static void SwapComponents(ref Vector2ul val)
		{
			val = (Vector2ul) (((Vector4ui) val).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
		}
		
		protected abstract ulong[][] CalculateKeySchedule();
	}
}
