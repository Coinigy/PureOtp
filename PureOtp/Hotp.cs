using PureOtp.Interfaces;
using PureOtp.Types;

namespace PureOtp
{
	/// <summary>
	/// Calculate HMAC-One-Time-Passwords (HOTP) from a secret key
	/// </summary>
	public class Hotp : Otp
	{
		/// <summary>
		/// Create an HOTP instance
		/// </summary>
		/// <param name="secretKey">The secret key to use in HOTP calculations</param>
		/// <param name="mode">The hash mode to use</param>
		public Hotp(byte[] secretKey, OtpHashMode mode = OtpHashMode.Sha1) : base(secretKey, mode)
		{
		}

		/// <summary>
		/// Create an HOTP instance
		/// </summary>
		/// <param name="secretKey">The secret key to use in HOTP calculations</param>
		/// <param name="mode">The hash mode to use</param>
		public Hotp(IKeyProvider secretKey, OtpHashMode mode = OtpHashMode.Sha1) : base(secretKey, mode)
		{
		}

		/// <summary>
		/// Takes a counter and produces an HOTP value
		/// </summary>
		/// <param name="counter">the counter to be incremented each time this method is called</param>
		/// <returns>Hotp</returns>
		public string ComputeHotp(long counter) => Compute(counter, HashMode);

		/// <remarks>
		/// This method mainly exists for unit tests.
		/// The RFC defines a decimal value in the test table that is an
		/// intermediate step to a final HOTP value
		/// </remarks>
		internal long ComputeHotpDecimal(long counter, OtpHashMode mode) => CalculateOtp(KeyUtilities.GetBigEndianBytes(counter), mode);

		/// <summary>
		/// Takes a counter and runs it through the HOTP algorithm.
		/// </summary>
		/// <param name="counter">Counter or step</param>
		/// <param name="mode">The hash mode to use</param>
		/// <returns>HOTP calculated code</returns>
		protected override string Compute(long counter, OtpHashMode mode) => Digits(ComputeHotpDecimal(counter, mode), 6);
	}
}
