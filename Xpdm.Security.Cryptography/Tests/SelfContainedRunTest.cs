using Mono.Simd;

namespace Xpdm.Security.Cryptography
{
	public static class Program
	{
		public static void Main()
		{
			var input = new ulong[]{ 0x0001020304050607UL, 0xffeeddccbbaa9988UL, 0x08090a0b0c0d0e0fUL, 0x0011223344556677 };
			var tweak = new ulong[]{ 0xa55aa55aa55aa55aUL, 0x137ff731019e7980UL };
			var key = new ulong[]{ 9457023847234UL, 472570192431239UL, 1234728012456UL, 54774345235234UL };
			
			var output = new ulong[4];
			var Cipher = new Threefish256();
			Cipher.SetKey(key);
			Cipher.SetTweak(tweak);			
			Cipher.Encrypt(input, output);
			
			var outputSimd = new ulong[4];
			var CipherSimd = new Threefish256Simd();
			CipherSimd.SetKey(key);
			CipherSimd.SetTweak(tweak);
			CipherSimd.Encrypt(input, outputSimd);
			
			System.Console.WriteLine("Encrypt:");
			System.Console.WriteLine("{0:X16} {1:X16} {2:X16} {3:X16}", output[0], output[1], output[2], output[3]);
			System.Console.WriteLine("{0:X16} {1:X16} {2:X16} {3:X16}", outputSimd[0], outputSimd[1], outputSimd[2], outputSimd[3]);
			
			if (output[0] == outputSimd[0] && output[1] == outputSimd[1] && output[2] == outputSimd[2] && output[3] == outputSimd[3])
			{
				System.Console.WriteLine("Good!");
			}
			else
			{
				System.Console.WriteLine("Bad...");
			}

			var crossTest = new ulong[4];
			var crossTestSimd = new ulong[4];
			Cipher.Decrypt(outputSimd, crossTest);
			CipherSimd.Decrypt(output, crossTestSimd);
			
			System.Console.WriteLine("Cross Decrypt:");
			System.Console.WriteLine("{0:X16} {1:X16} {2:X16} {3:X16}", crossTest[0], crossTest[1], crossTest[2], crossTest[3]);
			System.Console.WriteLine("{0:X16} {1:X16} {2:X16} {3:X16}", crossTestSimd[0], crossTestSimd[1], crossTestSimd[2], crossTestSimd[3]);
			
			if (crossTest[0] == crossTestSimd[0] && crossTest[1] == crossTestSimd[1] && crossTest[2] == crossTestSimd[2] && crossTest[3] == crossTestSimd[3])
			{
				System.Console.WriteLine("Good!");
			}
			else
			{
				System.Console.WriteLine("Bad...");
				//System.Environment.Exit(1);
				//return;
			}

			const int COUNT = 100000000;
			const int UNROLL = 100;
			
			System.Console.WriteLine("Speed test of {0} iterations with an unroll of {1}", COUNT, UNROLL);
			
			var stopwatch = new System.Diagnostics.Stopwatch();
			long t1, tp;
			int p = 2;
			
			System.Console.WriteLine("Encryption:");
			stopwatch.Start();
			for (int i = 0; i < COUNT / UNROLL; ++i)
			{
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
				Cipher.Encrypt(output, output);
			}
			stopwatch.Stop();
			System.Console.WriteLine("Non Simd: {0}, Average: {1}, Clocks per Byte: {2}", 
			                         stopwatch.Elapsed,
			                         new System.TimeSpan(stopwatch.ElapsedTicks / COUNT),
			                         stopwatch.ElapsedTicks * 1.6e9d / (System.TimeSpan.TicksPerSecond * COUNT * 4 * sizeof(ulong)));
			t1 = stopwatch.ElapsedTicks;
			
			stopwatch.Reset();
			stopwatch.Start();
			for (int i = 0; i < COUNT / UNROLL; ++i)
			{
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
				CipherSimd.Encrypt(outputSimd, outputSimd);
			}
			stopwatch.Stop();
			System.Console.WriteLine("    Simd: {0}, Average: {1}, Clocks per Byte: {2}", 
			                         stopwatch.Elapsed,
			                         new System.TimeSpan(stopwatch.ElapsedTicks / COUNT),
			                         stopwatch.ElapsedTicks * 1.6e9d / (System.TimeSpan.TicksPerSecond * COUNT * 4 * sizeof(ulong)));
			tp = stopwatch.ElapsedTicks;
			System.Console.WriteLine("Speedup with parallelism = {0}: {1}", p, t1/(double)tp);
		 	System.Console.WriteLine("Efficiency: {0:##0.00%}", t1/(double)(p * tp));
			
			stopwatch.Reset();
			System.Console.WriteLine("Decryption:");
			stopwatch.Start();
			for (int i = 0; i < COUNT / UNROLL; ++i)
			{
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
				Cipher.Decrypt(crossTest, crossTest);
			}
			stopwatch.Stop();
			System.Console.WriteLine("Non Simd: {0}, Average: {1}, Clocks per Byte: {2}", 
			                         stopwatch.Elapsed,
			                         new System.TimeSpan(stopwatch.ElapsedTicks / COUNT),
			                         stopwatch.ElapsedTicks * 1.6e9d / (System.TimeSpan.TicksPerSecond * COUNT * 4 * sizeof(ulong)));
			t1 = stopwatch.ElapsedTicks;
			
			stopwatch.Reset();
			stopwatch.Start();
			for (int i = 0; i < COUNT / UNROLL; ++i)
			{
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
				CipherSimd.Decrypt(crossTestSimd, crossTestSimd);
			}
			stopwatch.Stop();
			System.Console.WriteLine("    Simd: {0}, Average: {1}, Clocks per Byte: {2}", 
			                         stopwatch.Elapsed,
			                         new System.TimeSpan(stopwatch.ElapsedTicks / COUNT),
			                         stopwatch.ElapsedTicks * 1.6e9d / (System.TimeSpan.TicksPerSecond * COUNT * 4 * sizeof(ulong)));
			tp = stopwatch.ElapsedTicks;
			System.Console.WriteLine("Speedup with parallelism = {0}: {1}", p, t1/(double)tp);
		 	System.Console.WriteLine("Efficiency: {0:##0.00%}", t1/(double)(p * tp));

			stopwatch.Reset();
			stopwatch.Start();
			for (int i = 0; i < COUNT / UNROLL; ++i) ;
			stopwatch.Stop();
			System.Console.WriteLine("Overhead: {0}, Average: {1}ns, Clocks per Byte: {2}", stopwatch.Elapsed, stopwatch.ElapsedTicks/(double)System.TimeSpan.TicksPerSecond * 1000000000 / COUNT, stopwatch.ElapsedTicks * 1.6e9d / (System.TimeSpan.TicksPerSecond * COUNT * 4 * sizeof(ulong)));
		}
	}
}
