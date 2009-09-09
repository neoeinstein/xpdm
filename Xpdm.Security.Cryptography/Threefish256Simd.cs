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
			// Align the stack to a 16-byte boundary
			ulong z = 0;
			// Cache the block and key schedule
			Vector2ul bZero = new Vector2ul(z),
				      bOne = new Vector2ul(0, 1);
			Vector2ul bA = Vector2ul.LoadAligned(ref bZero),
				      bB = Vector2ul.LoadAligned(ref bZero),
				      bTempA = Vector2ul.LoadAligned(ref bZero),
				      bTempB = Vector2ul.LoadAligned(ref bZero);
			Vector2ul k0 = new Vector2ul(m_ExpandedKey[0], m_ExpandedKey[2]),
				      k1 = new Vector2ul(m_ExpandedKey[1], m_ExpandedKey[3]),
				      k2 = new Vector2ul(m_ExpandedKey[2], m_ExpandedKey[4]),
				      k3 = new Vector2ul(m_ExpandedKey[3], m_ExpandedKey[0]),
				      k4 = new Vector2ul(m_ExpandedKey[4], m_ExpandedKey[1]);
			Vector2ul t0h = new Vector2ul(m_ExpandedTweak[0], 0),
				      t0l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t0h)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)), 
				      t1h = new Vector2ul(m_ExpandedTweak[1], 0),
				      t1l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t1h)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)),
				      t2h = new Vector2ul(m_ExpandedTweak[2], 0),
				      t2l = (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref t2h)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY));
			Vector2ul subkey = Vector2ul.LoadAligned(ref bOne);

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
			
			// Round 1, Subkey 0
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 2
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 3
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 4
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 5, Subkey 1
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 6
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 7
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 8
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			
			// Round 9, Subkey 2
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 10
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 11
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 12
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 13, Subkey 3
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 14
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 15
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 16
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 17, Subkey 4
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 18
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 19
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 20
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 21, Subkey 5
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 22
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 23
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 24
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 25, Subkey 6
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 26
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 27
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 28
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 29, Subkey 7
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 30
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 31
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 32
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 33, Subkey 8
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 34
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 35
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 36
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 37, Subkey 9
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 38
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 39
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 40
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 41, Subkey 10
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 42
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 43
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 44
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 45, Subkey 11
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 46
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 47
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 48
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 49, Subkey 12
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 50
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 51
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 52
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 53, Subkey 13
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 54
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 55
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 56
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 57, Subkey 14
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 58
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 59
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 60
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 61, Subkey 15
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k0) + Vector2ul.LoadAligned(ref t1l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 62
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 63
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 64
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 65, Subkey 16
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t1h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k1) + Vector2ul.LoadAligned(ref t2l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 56 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 56));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) <<  5 | Vector2ul.LoadAligned(ref bTempA) >> (64 -  5));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 66
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 28 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 28));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 36 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 36));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 67
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 46 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 46));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 13 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 13));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 68
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 44 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 44));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 58 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 58));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Round 69, Subkey 17
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t2h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k2) + Vector2ul.LoadAligned(ref t0l));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 20 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 20));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 26 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 26));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 70
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 35 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 35));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 53 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 53));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 71
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 42 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 42));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 11 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 11));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));
			// Round 72
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bZero).UnpackLow(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bZero).UnpackHigh(Vector2ul.LoadAligned(ref bB)));
			Vector2ul.StoreAligned(ref bTempB, Vector2ul.LoadAligned(ref bTempB) << 50 | Vector2ul.LoadAligned(ref bTempB) >> (64 - 50));
			Vector2ul.StoreAligned(ref bTempA, Vector2ul.LoadAligned(ref bTempA) << 59 | Vector2ul.LoadAligned(ref bTempA) >> (64 - 59));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bTempA).UnpackHigh(Vector2ul.LoadAligned(ref bTempB)));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref bB) ^ Vector2ul.LoadAligned(ref bA));
			Vector2ul.StoreAligned(ref bB, (Vector2ul) (((Vector4ui) Vector2ul.LoadAligned(ref bB)).Shuffle(ShuffleSel.XFromZ | ShuffleSel.YFromW | ShuffleSel.ZFromX | ShuffleSel.WFromY)));

			// Subkey 18
			Vector2ul.StoreAligned(ref subkey, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bOne));
			Vector2ul.StoreAligned(ref bB, Vector2ul.LoadAligned(ref subkey) + Vector2ul.LoadAligned(ref bB) + Vector2ul.LoadAligned(ref k4) + Vector2ul.LoadAligned(ref t0h));
			Vector2ul.StoreAligned(ref bA, Vector2ul.LoadAligned(ref bA) + Vector2ul.LoadAligned(ref k3) + Vector2ul.LoadAligned(ref t1l));
			
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
