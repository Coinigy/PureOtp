namespace PureOtp
{
	/// <summary>
	/// Several constants used for the URL format
	/// </summary>
	internal class UrlConstants
	{
		public const string SecretParameter = "secret";
		public const string AlgorithmParameter = "algorithm";
		public const string PeriodParameter = "period";
		public const string CounterParameter = "counter";
		public const string DigitsParameter = "digits";
		public const string ParameterCreation = "&{0}={1}";
		public const string UrlValidationPatterm = @"^[^:]+://[^/]+/[^/\?]+(/?\?[^/]+)?$";
	}
}
