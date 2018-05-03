using System;
using System.Text;
using System.Threading.Tasks;
using PureOtp;

namespace PureOtpTest
{
    class Program
    {
        static void Main(string[] args)
        {
	        const string secret = "MyTestSecret";
	        var totp = new PureOtp.Totp(Encoding.UTF8.GetBytes(secret));
			RETRY:
	        var otpCode = totp.ComputeTotp();
	        var isGood = totp.VerifyTotp(otpCode, out var timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay);
	        if (isGood)
	        {
		        Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("Secret: " + secret + " Code: " + otpCode + " Result: passed");
				Console.ResetColor();
	        }
	        else
	        {
				Console.ForegroundColor = ConsoleColor.Red;
		        Console.WriteLine("Secret: " + secret + " Code: " + otpCode + " Result: failed");
		        Console.ResetColor();
			}

			Console.WriteLine();
            Console.WriteLine("Press 'r' key to run again, press 'w' to wait 30 seconds for new code before runing again");
	        var cres = Console.ReadKey();
	        Console.Write(new string(' ', Console.WindowWidth));
	        Console.SetCursorPosition(0, Console.CursorTop - 2);
	        Console.Write(new string(' ', Console.WindowWidth));
			Console.SetCursorPosition(0, Console.CursorTop);
	        Console.Write(new string(' ', Console.WindowWidth));
	        Console.SetCursorPosition(0, Console.CursorTop - 1);
			switch (cres.KeyChar)
	        {
				case 'R':
		        case 'r':
					Console.SetCursorPosition(0, Console.CursorTop - 1);
					Console.Write("RETRYING" + new string(' ', Console.WindowWidth-8));
			        goto RETRY;
				case 'W':
		        case 'w':
					Console.SetCursorPosition(0, Console.CursorTop - 1);
					Console.Write("RETRYING in 30 seconds" + new string(' ', Console.WindowWidth - 22));
					Task.Delay(10000).Wait();
					Console.SetCursorPosition(12, Console.CursorTop -1);
					Console.Write("20 seconds");
					Task.Delay(10000).Wait();
					Console.SetCursorPosition(12, Console.CursorTop);
					Console.Write("10 seconds");
					Task.Delay(10000).Wait();
					Console.SetCursorPosition(0, Console.CursorTop);
					Console.Write("RETRYING" + new string(' ', Console.WindowWidth - 8));
					goto RETRY;
	        }
        }
    }
}
