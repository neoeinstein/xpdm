using Mono.Simd;

namespace Xpdm.Security.Cryptography
{
    internal sealed class Threefish256Simd : ThreefishCipherSimd
    {
        const int CIPHER_SIZE = 256;
        const int CIPHER_QWORDS = CIPHER_SIZE / 64;
        const int EXPANDED_KEY_SIZE = CIPHER_QWORDS + 1;
		const int NUM_ROUNDS = 72;
		const int SUBKEY_COUNT = NUM_ROUNDS / 4 + 1;

        public Threefish256Simd()
        {
            // Create the expanded key array
            m_ExpandedKey = new ulong[EXPANDED_KEY_SIZE];
        }
		
		protected override ulong[][] CalculateKeySchedule()
		{
            ulong k0 = m_ExpandedKey[0], k1 = m_ExpandedKey[1],
                  k2 = m_ExpandedKey[2], k3 = m_ExpandedKey[3],
                  k4 = m_ExpandedKey[4];
            ulong t0 = m_ExpandedTweak[0], t1 = m_ExpandedTweak[1],
                  t2 = m_ExpandedTweak[2];

			ulong[][] schedule = new ulong[][]
			{
				new ulong[] { k0, k2 + t1, k1 + t0, k3 },
				new ulong[] { k1, k3 + t2, k2 + t1, k4 + 1 },
				new ulong[] { k2, k4 + t0, k3 + t2, k0 + 2 },
				new ulong[] { k3, k0 + t1, k4 + t0, k1 + 3 },
				new ulong[] { k4, k1 + t2, k0 + t1, k2 + 4 },
				new ulong[] { k0, k2 + t0, k1 + t2, k3 + 5 },
				new ulong[] { k1, k3 + t1, k2 + t0, k4 + 6 },
				new ulong[] { k2, k4 + t2, k3 + t1, k0 + 7 },
				new ulong[] { k3, k0 + t0, k4 + t2, k1 + 8 },
				new ulong[] { k4, k1 + t1, k0 + t0, k2 + 9 },
				new ulong[] { k0, k2 + t2, k1 + t1, k3 + 10 },
				new ulong[] { k1, k3 + t0, k2 + t2, k4 + 11 },
				new ulong[] { k2, k4 + t1, k3 + t0, k0 + 12 },
				new ulong[] { k3, k0 + t2, k4 + t1, k1 + 13 },
				new ulong[] { k4, k1 + t0, k0 + t2, k2 + 14 },
				new ulong[] { k0, k2 + t1, k1 + t0, k3 + 15 },
				new ulong[] { k1, k3 + t2, k2 + t1, k4 + 16 },
				new ulong[] { k2, k4 + t0, k3 + t2, k0 + 17 },
				new ulong[] { k3, k0 + t1, k4 + t0, k1 + 18 },
			};
			
			return schedule;
		}
		
		private static void GetInputVectors(ulong[] input, out Vector2ul bA, out Vector2ul bB)
		{
			Vector2ul bTemp;
			if (input.IsAligned(0))
			{
				bA = input.GetVectorAligned(0);
				bTemp = input.GetVectorAligned(2);
				bB = bA.UnpackHigh(bTemp);
				bA = bA.UnpackLow(bTemp);
			}
			else
			{
				bA = input.GetVector(0);
				bTemp = input.GetVector(2);
				bB = bA.UnpackHigh(bTemp);
				bA = bA.UnpackLow(bTemp);
			}				
		}
		
		private static void UnpackOutput(ulong[] output, ref Vector2ul bA, ref Vector2ul bB)
		{
			if(output.IsAligned(0))
			{
				output.SetVectorAligned(bA.UnpackLow(bB), 0);
				output.SetVectorAligned(bA.UnpackHigh(bB), 2);
			}
			else
			{
				output.SetVector(bA.UnpackLow(bB), 0);
				output.SetVector(bA.UnpackHigh(bB), 2);
			}
		}

        public override void Encrypt(ulong[] input, ulong[] output)
        {
            // Cache the block and key schedule
			ulong[][] keySchedule = CalculateKeySchedule();
			Vector2ul bA, bB, bTempA, bTempB;

			if (input.IsAligned(0))
			{
				bA = input.GetVectorAligned(0);
				bTempA = input.GetVectorAligned(2);
				bB = bA.UnpackHigh(bTempA);
				bA = bA.UnpackLow(bTempA);
			}
			else
			{
				bA = input.GetVector(0);
				bTempA = input.GetVector(2);
				bB = bA.UnpackHigh(bTempA);
				bA = bA.UnpackLow(bTempA);
			}
			
			bA = bA + keySchedule[0].GetVectorAligned(0);
			bB = bB + keySchedule[0].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[1].GetVectorAligned(0);
			bB = bB + keySchedule[1].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[2].GetVectorAligned(0);
			bB = bB + keySchedule[2].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[3].GetVectorAligned(0);
			bB = bB + keySchedule[3].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[4].GetVectorAligned(0);
			bB = bB + keySchedule[4].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[5].GetVectorAligned(0);
			bB = bB + keySchedule[5].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[6].GetVectorAligned(0);
			bB = bB + keySchedule[6].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[7].GetVectorAligned(0);
			bB = bB + keySchedule[7].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[8].GetVectorAligned(0);
			bB = bB + keySchedule[8].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[9].GetVectorAligned(0);
			bB = bB + keySchedule[9].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[10].GetVectorAligned(0);
			bB = bB + keySchedule[10].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[11].GetVectorAligned(0);
			bB = bB + keySchedule[11].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[12].GetVectorAligned(0);
			bB = bB + keySchedule[12].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[13].GetVectorAligned(0);
			bB = bB + keySchedule[13].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[14].GetVectorAligned(0);
			bB = bB + keySchedule[14].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[15].GetVectorAligned(0);
			bB = bB + keySchedule[15].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[16].GetVectorAligned(0);
			bB = bB + keySchedule[16].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA <<  5 | bTempA >> (64 -  5);
			bTempB = bTempB << 56 | bTempB >> (64 - 56);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 36 | bTempA >> (64 - 36);
			bTempB = bTempB << 28 | bTempB >> (64 - 28);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 13 | bTempA >> (64 - 13);
			bTempB = bTempB << 46 | bTempB >> (64 - 46);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 58 | bTempA >> (64 - 58);
			bTempB = bTempB << 44 | bTempB >> (64 - 44);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			
			bA = bA + keySchedule[17].GetVectorAligned(0);
			bB = bB + keySchedule[17].GetVectorAligned(2);
			
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 26 | bTempA >> (64 - 26);
			bTempB = bTempB << 20 | bTempB >> (64 - 20);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 53 | bTempA >> (64 - 53);
			bTempB = bTempB << 35 | bTempB >> (64 - 35);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 11 | bTempA >> (64 - 11);
			bTempB = bTempB << 42 | bTempB >> (64 - 42);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			bA = bA + bB;
			bTempA = Vector2ul.Zero.UnpackLow(bB);
			bTempB = Vector2ul.Zero.UnpackHigh(bB);
			bTempA = bTempA << 59 | bTempA >> (64 - 59);
			bTempB = bTempB << 50 | bTempB >> (64 - 50);
			bB = bTempA.UnpackHigh(bTempB);
			bB = bB ^ bA;
			bB = (Vector2ul) (((Vector4ui) bB).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));

			bA = bA + keySchedule[18].GetVectorAligned(0);
			bB = bB + keySchedule[18].GetVectorAligned(2);
			
			if(output.IsAligned(0))
			{
				output.SetVectorAligned(bA.UnpackLow(bB), 0);
				output.SetVectorAligned(bA.UnpackHigh(bB), 2);
			}
			else
			{
				output.SetVector(bA.UnpackLow(bB), 0);
				output.SetVector(bA.UnpackHigh(bB), 2);
			}
        }

        public override void Decrypt(ulong[] input, ulong[] output)
        {
            // Cache the block and key schedule
			ulong[][] keySchedule = CalculateKeySchedule();
			Vector2ul bA, bB;
			GetInputVectors(input, out bA, out bB);

			bA = bA - keySchedule[18].GetVectorAligned(0);
			bB = bB - keySchedule[18].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[17].GetVectorAligned(0);
			bB = bB - keySchedule[17].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[16].GetVectorAligned(0);
			bB = bB - keySchedule[16].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[15].GetVectorAligned(0);
			bB = bB - keySchedule[15].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[14].GetVectorAligned(0);
			bB = bB - keySchedule[14].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[13].GetVectorAligned(0);
			bB = bB - keySchedule[13].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[12].GetVectorAligned(0);
			bB = bB - keySchedule[12].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[11].GetVectorAligned(0);
			bB = bB - keySchedule[11].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[10].GetVectorAligned(0);
			bB = bB - keySchedule[10].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[9].GetVectorAligned(0);
			bB = bB - keySchedule[9].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[8].GetVectorAligned(0);
			bB = bB - keySchedule[8].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[7].GetVectorAligned(0);
			bB = bB - keySchedule[7].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[6].GetVectorAligned(0);
			bB = bB - keySchedule[6].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[5].GetVectorAligned(0);
			bB = bB - keySchedule[5].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[4].GetVectorAligned(0);
			bB = bB - keySchedule[4].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[3].GetVectorAligned(0);
			bB = bB - keySchedule[3].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[2].GetVectorAligned(0);
			bB = bB - keySchedule[2].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 59, 50);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 11, 42);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 53, 35);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 26, 20);

			bA = bA - keySchedule[1].GetVectorAligned(0);
			bB = bB - keySchedule[1].GetVectorAligned(2);

			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 58, 44);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 13, 46);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB, 36, 28);
			SwapComponents(ref bB);
			UnMix(ref bA, ref bB,  5, 56);

			bA = bA - keySchedule[0].GetVectorAligned(0);
			bB = bB - keySchedule[0].GetVectorAligned(2);
			
			UnpackOutput(output, ref bA, ref bB);
        }
    }
}
