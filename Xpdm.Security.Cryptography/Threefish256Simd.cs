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
			// When Vector2ul is first argument in this method, it isn't aligned... align it.
    		ulong block = 0;
	        // Cache the block and key schedule
			Vector2ul bZero = new Vector2ul(block);
			Vector2ul bA = Vector2ul.LoadAligned(ref bZero);
			Vector2ul bB = Vector2ul.LoadAligned(ref bZero);
			Vector2ul bTempA = Vector2ul.LoadAligned(ref bZero);
			Vector2ul bTempB = Vector2ul.LoadAligned(ref bZero);
			ulong[][] keySchedule = CalculateKeySchedule();

			if (input.IsAligned(0))
			{
				Vector2ul.StoreAligned(ref bA, input.GetVectorAligned(0));
				Vector2ul.StoreAligned(ref bTempA, input.GetVectorAligned(2));
			}
			else
			{
				Vector2ul.StoreAligned(ref bA, input.GetVector(0));
				Vector2ul.StoreAligned(ref bTempA, input.GetVector(2));
			}
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bTempA)));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bTempA)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[0].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[0].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[1].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[1].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[2].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[2].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[3].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[3].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[4].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[4].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[5].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[5].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[6].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[6].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[7].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[7].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[8].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[8].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[9].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[9].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[10].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[10].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[11].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[11].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[12].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[12].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[13].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[13].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[14].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[14].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[15].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[15].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[16].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[16].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[17].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + keySchedule[17].GetVectorAligned(0));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + keySchedule[18].GetVectorAligned(2));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) + keySchedule[18].GetVectorAligned(0));
			
			if(output.IsAligned(0))
			{
				output.SetVectorAligned(Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bB)), 0);
				output.SetVectorAligned(Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bB)), 2);
			}
			else
			{
				output.SetVector(Vector2ul.LoadAligned(ref bA).UnpackLow(Vector2ul.LoadAligned(ref bB)), 0);
				output.SetVector(Vector2ul.LoadAligned(ref bA).UnpackHigh(Vector2ul.LoadAligned(ref bB)), 2);
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
