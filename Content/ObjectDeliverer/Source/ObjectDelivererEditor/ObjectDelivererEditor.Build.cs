// Copyright 2019 ayumax. All Rights Reserved.
using UnrealBuildTool;
using System.IO;

public class ObjectDelivererEditor : ModuleRules
{
	public ObjectDelivererEditor(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;

		PublicIncludePaths.AddRange(
			new string[] {
			}
		);

		PrivateIncludePaths.AddRange(
			new string[] {
			}
		);

		PublicDependencyModuleNames.AddRange(
			new string[]
			{
				"Core",
				"CoreUObject",
				"ObjectDeliverer",
			}
		);

		PrivateDependencyModuleNames.AddRange(
			new string[]
			{
				"ToolMenus",
				"Slate",
				"SlateCore",
				"EditorStyle",
				"InputCore",
				"LevelEditor",
				"UnrealEd",
				"AssetTools",
			}
		);

		DynamicallyLoadedModuleNames.AddRange(
			new string[]
			{
			}
		);
	}
}
