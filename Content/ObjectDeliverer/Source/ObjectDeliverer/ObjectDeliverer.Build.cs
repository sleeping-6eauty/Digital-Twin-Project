// Copyright 2019 ayumax. All Rights Reserved.
using System.IO;

namespace UnrealBuildTool.Rules
{
	public class ObjectDeliverer : ModuleRules
	{
		public ObjectDeliverer(ReadOnlyTargetRules Target) : base(Target)
		{
			PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;

			PublicIncludePaths.Add(Path.Combine(ModuleDirectory, "Private"));

			PublicDependencyModuleNames.AddRange(
				new string[]
			{
				"Core",
				"CoreUObject",
				"Engine",
				"Sockets",
				"Networking",
				"Json",
				"JsonUtilities",
				"WebSockets"
			}
		);

			PrivateDependencyModuleNames.AddRange(
				new string[]
				{
					"SSL"
				}
			);

			bool bPlatformSupportsSSL =
				Target.Platform == UnrealTargetPlatform.Mac ||
				Target.Platform == UnrealTargetPlatform.Win64 ||
				Target.IsInPlatformGroup(UnrealPlatformGroup.Unix) ||
				Target.Platform == UnrealTargetPlatform.IOS ||
				Target.Platform == UnrealTargetPlatform.Android;

			if (bPlatformSupportsSSL)
			{
				AddEngineThirdPartyPrivateStaticDependencies(Target, "OpenSSL");
			}

			if (Target.Platform == UnrealTargetPlatform.Win64)
			{
				PublicSystemLibraries.Add("crypt32.lib");
			}

			if (Target.Platform == UnrealTargetPlatform.Mac ||
				Target.Platform == UnrealTargetPlatform.IOS)
			{
				PublicFrameworks.Add("Security");
			}
		}
	}
}
