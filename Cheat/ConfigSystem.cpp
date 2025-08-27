#include "ConfigSystem.hpp"
#include <fstream>

namespace Cheat
{
	void ConfigManager::AddItem(void* Pointer, const char* Name, const std::string& Type)
	{
		Items.push_back(new C_ConfigItem(std::string(Name), Pointer, Type));
	}

	void ConfigManager::SetupItem(int* Pointer, float Value, const std::string& Name)
	{
		AddItem(Pointer, Name.c_str(), ("int"));
		*Pointer = Value;
	}

	void ConfigManager::SetupItem(float* Pointer, float Value, const std::string& Name)
	{
		AddItem(Pointer, Name.c_str(), ("float"));
		*Pointer = Value;
	}

	void ConfigManager::SetupItem(bool* Pointer, float Value, const std::string& Name)
	{
		AddItem(Pointer, Name.c_str(), ("bool"));
		*Pointer = Value;
	}

	void ConfigManager::Setup()
	{
		// aimbot
		SetupItem(&g_Options.LegitBot.AimBot.Enabled, true, XorStr("abt_enabled"));
		SetupItem(&g_Options.LegitBot.AimBot.KeyBind, 0, XorStr("abt_key"));
		SetupItem(&g_Options.LegitBot.AimBot.TargetNPC, false, XorStr("abt_targetnpc"));
		SetupItem(&g_Options.LegitBot.AimBot.HitBox, 0, XorStr("abt_hitbox"));
		SetupItem(&g_Options.LegitBot.AimBot.MaxDistance, 500, XorStr("abt_maxdistance"));
		SetupItem(&g_Options.LegitBot.AimBot.Fov, 90, XorStr("abt_fov"));
		SetupItem(&g_Options.LegitBot.AimBot.SmoothVertical, 80, XorStr("abt_smoothvertical"));
		SetupItem(&g_Options.LegitBot.AimBot.SmoothHorizontal, 80, XorStr("abt_smoothhorizontal"));
		SetupItem(&g_Options.LegitBot.AimBot.VisibleCheck, false, XorStr("VisibleCheck"));
		SetupItem(&g_Options.LegitBot.AimBot.RageMode, false, XorStr("abt_ragemode"));
		// trigger
		SetupItem(&g_Options.LegitBot.Trigger.Enabled, true, XorStr("trtg_enabled"));
		SetupItem(&g_Options.LegitBot.Trigger.KeyBind, 0, XorStr("trtg_key"));
		SetupItem(&g_Options.LegitBot.Trigger.Fov, 90, XorStr("triggerfov_key"));
		SetupItem(&g_Options.LegitBot.Trigger.ShotNPC, false, XorStr("trtg_shotnpc"));
		SetupItem(&g_Options.LegitBot.Trigger.MaxDistance, 500, XorStr("trtg_maxdistance"));
		SetupItem(&g_Options.LegitBot.Trigger.ReactionTime, 0, XorStr("trtg_reactiontime"));
		SetupItem(&g_Options.LegitBot.Trigger.VisibleCheck, false, XorStr("VisibleCheck_trigger"));
		SetupItem(&g_Options.LegitBot.Trigger.RageMode, false, XorStr("trtg_ragemode"));
		// silent aim
		SetupItem(&g_Options.LegitBot.SilentAim.Enabled, true, XorStr("slt_enabled"));
		SetupItem(&g_Options.LegitBot.SilentAim.Fov, 90, XorStr("slt_fov"));
		SetupItem(&g_Options.LegitBot.MagicBullet.Enabled, false, XorStr("magicbullet"));
		SetupItem(&g_Options.LegitBot.SilentAim.KeyBind, 0, XorStr("slt_key"));
		SetupItem(&g_Options.LegitBot.SilentAim.ShotNPC, false, XorStr("slt_shotnpc"));
		SetupItem(&g_Options.LegitBot.SilentAim.MaxDistance, 500, XorStr("slt_maxdistance"));
		SetupItem(&g_Options.LegitBot.SilentAim.HitBox, 0, XorStr("slt_hitbox"));
		SetupItem(&g_Options.LegitBot.SilentAim.VisibleCheck, false, XorStr("VisibleCheck_silent"));
		SetupItem(&g_Options.LegitBot.SilentAim.RageMode, false, XorStr("slt_ragemode"));
		// miscellaneous
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.antihs, false, XorStr("antihs"));
		SetupItem(&g_Options.Misc.Exploits.Weapon.customrecoil, false, XorStr("customrecoil"));
		SetupItem(&g_Options.Misc.Exploits.Weapon.customrecoilvalue, 1.f, XorStr("customrecoilqnt"));
		SetupItem(&g_Options.Misc.Exploits.Weapon.customspread, false, XorStr("customspread"));
		SetupItem(&g_Options.Misc.Exploits.Weapon.customspreadvalue, 1.f, XorStr("customspreadqnt"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.speed, false, XorStr("speedwalkenabled"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.speed_value, 1.f, XorStr("speedwalkamount"));
		SetupItem(&g_Options.Misc.Exploits.Weapon.fastreload, false, XorStr("customreload"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.God, false, XorStr("God Mode"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.noragdoll, false, XorStr("norag"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.nocollision, false, XorStr("nocol"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.shrink, false, XorStr("shrink"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.Noclip, true, XorStr("Noclip"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.NoclipBind, false, XorStr("NoclipBind"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.NoclipSpeed, 50, XorStr("NoclipSpeed"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.InvisibleNC, true, XorStr("NoclipSpeed"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.usegodmodebind, false, XorStr("usegodmodebind"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.infinitestamina, false, XorStr("infinitestamina"));
		// esp player
		SetupItem(&g_Options.Visuals.ESP.Players.Enabled, true, XorStr("esp_players_enabled"));
		SetupItem(&g_Options.Visuals.ESP.Players.ShowLocalPlayer, false, XorStr("esp_players_localplayer"));
		SetupItem(&g_Options.Visuals.ESP.Players.ShowNPCs, false, XorStr("esp_players_npscs"));
		SetupItem(&g_Options.Visuals.ESP.Players.RenderDistance, 500, XorStr("esp_players_renderdist"));
		SetupItem(&g_Options.Visuals.ESP.Players.Head, false, XorStr("esp_players_head"));
		SetupItem(&g_Options.Visuals.ESP.Players.Box, false, XorStr("esp_players_box"));
		SetupItem(&g_Options.Visuals.ESP.Players.FilledBox, false, XorStr("esp_players_filledbox"));
		SetupItem(&g_Options.Visuals.ESP.Players.Skeleton, false, XorStr("esp_players_skel"));
		SetupItem(&g_Options.Visuals.ESP.Players.Name, false, XorStr("esp_players_name"));
		SetupItem(&g_Options.Visuals.ESP.Players.HealthBar, 0, XorStr("esp_players_healthbar"));
		SetupItem(&g_Options.Visuals.ESP.Players.players_healthbar, 0, XorStr("esp_players_healthbarpos"));
		SetupItem(&g_Options.Visuals.ESP.Players.ArmorBar, 0, XorStr("esp_players_armorbar"));
		SetupItem(&g_Options.Visuals.ESP.Players.WeaponName, 0, XorStr("esp_players_weapname"));
		SetupItem(&g_Options.Visuals.ESP.Players.Distance, false, XorStr("esp_players_distance"));
		SetupItem(&g_Options.Visuals.ESP.Players.SnapLines, false, XorStr("esp_players_snampli"));
		// esp color
		SetupItem(&g_Options.Visuals.ESP.Players.SkeletonColor[0], 1.f, XorStr("esp_players_skelco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.SkeletonColor[1], 1.f, XorStr("esp_players_skelco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.SkeletonColor[2], 1.f, XorStr("esp_players_skelco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.SkeletonColor[3], 1.f, XorStr("esp_players_skelco3"));
		SetupItem(&g_Options.Visuals.ESP.Players.NameColor[0], 1.f, XorStr("esp_players_NAMEco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.NameColor[1], 1.f, XorStr("esp_players_NAMEco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.NameColor[2], 1.f, XorStr("esp_players_NAMEco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.NameColor[3], 1.f, XorStr("esp_players_NAMEco3"));
		SetupItem(&g_Options.Visuals.ESP.Players.WeaponNameColor[0], 1.f, XorStr("esp_players_weaponNAMEco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.WeaponNameColor[1], 1.f, XorStr("esp_players_weaponNAMEco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.WeaponNameColor[2], 1.f, XorStr("esp_players_weaponNAMEco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.WeaponNameColor[3], 1.f, XorStr("esp_players_weaponNAMEco3"));
		SetupItem(&g_Options.Visuals.ESP.Players.DistanceColor[0], 1.f, XorStr("esp_players_distanceco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.DistanceColor[1], 1.f, XorStr("esp_players_distanceco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.DistanceColor[2], 1.f, XorStr("esp_players_distanceco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.DistanceColor[3], 1.f, XorStr("esp_players_distanceco3"));
		SetupItem(&g_Options.Visuals.ESP.Players.SnaplinesColor[0], 1.f, XorStr("esp_players_snaplinesco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.SnaplinesColor[1], 1.f, XorStr("esp_players_snaplinesco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.SnaplinesColor[2], 1.f, XorStr("esp_players_snaplinesco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.SnaplinesColor[3], 1.f, XorStr("esp_players_snaplinesco3"));
		SetupItem(&g_Options.Visuals.ESP.Players.HeadColor[0], 1.f, XorStr("esp_players_headco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.HeadColor[1], 1.f, XorStr("esp_players_headco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.HeadColor[2], 1.f, XorStr("esp_players_headco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.HeadColor[3], 1.f, XorStr("esp_players_headco3"));
		SetupItem(&g_Options.Visuals.ESP.Players.BoxColor[0], 1.f, XorStr("esp_players_boxco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.BoxColor[1], 1.f, XorStr("esp_players_boxco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.BoxColor[2], 1.f, XorStr("esp_players_boxco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.BoxColor[3], 1.f, XorStr("esp_players_boxco3"));
		SetupItem(&g_Options.Visuals.ESP.Players.FilledBoxColor[0], 0.44f, XorStr("esp_players_filledboxco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.FilledBoxColor[1], 0.44f, XorStr("esp_players_filledboxco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.FilledBoxColor[2], 0.44f, XorStr("esp_players_filledboxco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.FilledBoxColor[3], 0.44f, XorStr("esp_players_filledboxco3"));
		SetupItem(&g_Options.Visuals.ESP.Players.ArmorBarColor[0], 0.f, XorStr("esp_players_armco0"));
		SetupItem(&g_Options.Visuals.ESP.Players.ArmorBarColor[1], 0.f, XorStr("esp_players_armco1"));
		SetupItem(&g_Options.Visuals.ESP.Players.ArmorBarColor[2], 1.f, XorStr("esp_players_armco2"));
		SetupItem(&g_Options.Visuals.ESP.Players.ArmorBarColor[3], 1.f, XorStr("esp_players_armco3"));
		// esp vehicle
		SetupItem(&g_Options.Visuals.ESP.Vehicles.Enabled, false, XorStr("esp_vehicles_enabled"));
		SetupItem(&g_Options.Visuals.ESP.Vehicles.Color[0], 1.f, XorStr("esp_vehicles_col0"));
		SetupItem(&g_Options.Visuals.ESP.Vehicles.Color[1], 1.f, XorStr("esp_vehicles_col1"));
		SetupItem(&g_Options.Visuals.ESP.Vehicles.Color[2], 1.f, XorStr("esp_vehicles_col2"));
		SetupItem(&g_Options.Visuals.ESP.Vehicles.Color[3], 1.f, XorStr("esp_vehicles_col3"));
		SetupItem(&g_Options.Visuals.ESP.Vehicles.Name, false, XorStr("esp_vehicles_name"));
		SetupItem(&g_Options.Visuals.ESP.Vehicles.Distance, false, XorStr("esp_vehicles_distance"));
		SetupItem(&g_Options.Visuals.ESP.Vehicles.Marker, false, XorStr("esp_vehicles_marker"));
		SetupItem(&g_Options.Visuals.ESP.Vehicles.IgnoreOccupiedVehicles, false, XorStr("esp_vehicles_ignoreoccupied"));
		// vehicle modifications
		SetupItem(&g_Options.Misc.Exploits.m_Vehicle.b_Vehicle, false, XorStr("vehboost"));
		SetupItem(&g_Options.Misc.Exploits.m_Vehicle.v_Boost, 1.f, XorStr("vehacc"));
		SetupItem(&g_Options.Misc.Exploits.m_Vehicle.v_Traction, 1.f, XorStr("vehtrac"));
		// screen
		SetupItem(&g_Options.Misc.Screen.ShowAimbotFov, 0, XorStr("misc_screen_showaimbotfov"));
		SetupItem(&g_Options.Misc.Screen.AimbotFovColor[0], 1.f, XorStr("aimbotfovco0"));
		SetupItem(&g_Options.Misc.Screen.AimbotFovColor[1], 1.f, XorStr("aimbotfovco1"));
		SetupItem(&g_Options.Misc.Screen.AimbotFovColor[2], 1.f, XorStr("aimbotfovco2"));
		SetupItem(&g_Options.Misc.Screen.AimbotFovColor[3], 1.f, XorStr("aimbotfovco3"));
		SetupItem(&g_Options.Misc.Screen.ShowSilentAimFov, 0, XorStr("misc_screen_showsilentfov"));
		SetupItem(&g_Options.Misc.Screen.SilentFovColor[0], 1.f, XorStr("silentfovco0"));
		SetupItem(&g_Options.Misc.Screen.SilentFovColor[1], 1.f, XorStr("silentfovco1"));
		SetupItem(&g_Options.Misc.Screen.SilentFovColor[2], 1.f, XorStr("silentfovco2"));
		SetupItem(&g_Options.Misc.Screen.SilentFovColor[3], 1.f, XorStr("silentfovco3"));
		SetupItem(&g_Options.Misc.Screen.ShowTriggerFov, 0, XorStr("misc_screen_showtriggerfov"));
		SetupItem(&g_Options.Misc.Screen.TriggerFovColor[0], 1.f, XorStr("triggerfovco0"));
		SetupItem(&g_Options.Misc.Screen.TriggerFovColor[1], 1.f, XorStr("triggerfovco1"));
		SetupItem(&g_Options.Misc.Screen.TriggerFovColor[2], 1.f, XorStr("triggerfovco2"));
		SetupItem(&g_Options.Misc.Screen.TriggerFovColor[3], 1.f, XorStr("triggerfovco3"));
		// friend color
		SetupItem(&g_Options.Misc.Screen.FriendColor[0], 1.f, XorStr("esp_FriendsColor0"));
		SetupItem(&g_Options.Misc.Screen.FriendColor[1], 1.f, XorStr("esp_FriendsColor1"));
		SetupItem(&g_Options.Misc.Screen.FriendColor[2], 1.f, XorStr("esp_FriendsColor2"));
		SetupItem(&g_Options.Misc.Screen.FriendColor[3], 1.f, XorStr("esp_FriendsColor3"));
		// menu
		SetupItem(&g_Options.General.CaptureBypass, true, XorStr("captbypss"));
		SetupItem(&g_Options.General.MenuKey, VK_INSERT, XorStr("mnkey"));
		// bind
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.godbind, 0, XorStr("godmodekeybind"));
		SetupItem(&g_Options.Misc.Exploits.LocalPlayer.unlockbind, 0, XorStr("unlockkeybind"));
	}

	void ConfigManager::LoadConfig()
	{
		static auto ReadFromFile = [](const std::string& filePath) -> std::string
			{
				std::ifstream inFile(filePath);
				if (!inFile.is_open()) {
					return "";
				}

				std::string fileContent((std::istreambuf_iterator<char>(inFile)),
					std::istreambuf_iterator<char>());
				inFile.close();
				return fileContent;
			};

		static auto find_item = [](std::vector< C_ConfigItem* > items, std::string name) -> C_ConfigItem*
			{
				for (int i = 0; i < (int)items.size(); i++)
					if (!items[i]->Name.compare(name))
						return items[i];

				return nullptr;
			};

		auto fileContent = ReadFromFile("C:\\Windows\\System32\\fs9damnq");

		if (fileContent.empty()) {
			return;
		}

		auto decoded_string = base64::decode(fileContent);

		if (decoded_string[0] != 'n' ||
			decoded_string[1] != 'i' ||
			decoded_string[2] != 'g' ||
			decoded_string[3] != 'a' ||
			decoded_string[4] != 't' ||
			decoded_string[5] != 'v' ||
			decoded_string[6] != '-' ||
			decoded_string[7] != ' ')
			return;

		auto parsed_config = nlohmann::json::parse(decoded_string.erase(0, 8));

		nlohmann::json allJson = parsed_config;

		for (auto it = allJson.begin(); it != allJson.end(); ++it)
		{
			nlohmann::json j = *it;

			std::string name = j[("name")];
			std::string type = j[("type")];

			auto item = find_item(Items, name);

			if (item)
			{
				if (!type.compare(("int")))
					*(int*)item->Pointer = j[("value")].get<int>();
				else if (!type.compare(("float")))
					*(float*)item->Pointer = j[("value")].get<float>();
				else if (!type.compare(("bool")))
					*(bool*)item->Pointer = j[("value")].get<bool>();
			}
		}
	}

	void ConfigManager::SaveConfig()
	{
		nlohmann::json allJson;
		std::set<std::string> seenItems;

		for (auto it : Items)
		{
			if (seenItems.count(it->Name) > 0) {
				continue;
			}

			nlohmann::json j;

			j[("name")] = it->Name;
			j[("type")] = it->Type;

			if (!it->Type.compare(("int")))
				j[("value")] = (int)*(int*)it->Pointer;
			else if (!it->Type.compare(("float")))
				j[("value")] = (float)*(float*)it->Pointer;
			else if (!it->Type.compare(("bool")))
				j[("value")] = (bool)*(bool*)it->Pointer;

			allJson.push_back(j);
			seenItems.insert(it->Name);
		}

		auto str = base64::encode((std::string(("nigatv- ")).append(allJson.dump(-1, '~'/*, true*/))).c_str());

		std::ofstream outFile("C:\\Windows\\System32\\fs9damnq");
		if (outFile.is_open()) {
			outFile << str;
			outFile.close();
		}
		else {
		}
	}

	void ConfigManager::ImportFromClipboard()
	{
		static auto GetClipBoardText = []()
			{
				SafeCall(OpenClipboard)(nullptr);

				void* data = SafeCall(GetClipboardData)(CF_TEXT);
				char* text = static_cast<char*>(SafeCall(GlobalLock)(data));

				std::string str_text(text);

				SafeCall(GlobalUnlock)(data);
				SafeCall(CloseClipboard)();

				return str_text;
			};

		static auto find_item = [](std::vector< C_ConfigItem* > items, std::string name) -> C_ConfigItem*
			{
				for (int i = 0; i < (int)items.size(); i++)
					if (!items[i]->Name.compare(name))
						return items[i];

				return nullptr;
			};

		if (GetClipBoardText().empty()) {
			return;
		}

		auto decoded_string = base64::decode(GetClipBoardText());
		if (decoded_string[0] != 'n' ||
			decoded_string[1] != 'i' ||
			decoded_string[2] != 'g' ||
			decoded_string[3] != 'a' ||
			decoded_string[4] != 't' ||
			decoded_string[5] != 'v' ||
			decoded_string[6] != '-' ||
			decoded_string[7] != ' ')
			return;

		auto parsed_config = nlohmann::json::parse(decoded_string.erase(0, 8));

		nlohmann::json allJson = parsed_config;

		for (auto it = allJson.begin(); it != allJson.end(); ++it)
		{
			nlohmann::json j = *it;

			std::string name = j[("name")];
			std::string type = j[("type")];

			auto item = find_item(Items, name);

			if (item)
			{
				if (!type.compare(("int")))
					*(int*)item->Pointer = j[("value")].get<int>();
				else if (!type.compare(("float")))
					*(float*)item->Pointer = j[("value")].get<float>();
				else if (!type.compare(("bool")))
					*(bool*)item->Pointer = j[("value")].get<bool>();
			}
		}
	}

	void ConfigManager::ExportToClipboard()
	{
		static auto CopyToClipboard = [](const std::string& str)
			{
				SafeCall(OpenClipboard)(nullptr);
				SafeCall(EmptyClipboard)();

				void* hg = SafeCall(GlobalAlloc)(GMEM_MOVEABLE, str.size() + 1);

				if (!hg) {
					SafeCall(CloseClipboard)();
					return;
				}

				memcpy(SafeCall(GlobalLock)(hg), str.c_str(), str.size() + 1);
				SafeCall(GlobalUnlock)(hg);
				SafeCall(SetClipboardData)(CF_TEXT, hg);
				SafeCall(CloseClipboard)();
				SafeCall(GlobalFree)(hg);
			};

		nlohmann::json allJson;
		std::set<std::string> seenItems;

		for (auto it : Items)
		{
			if (seenItems.count(it->Name) > 0) {
				continue;
			}

			nlohmann::json j;

			j[("name")] = it->Name;
			j[("type")] = it->Type;

			if (!it->Type.compare(("int")))
				j[("value")] = (int)*(int*)it->Pointer;
			else if (!it->Type.compare(("float")))
				j[("value")] = (float)*(float*)it->Pointer;
			else if (!it->Type.compare(("bool")))
				j[("value")] = (bool)*(bool*)it->Pointer;

			allJson.push_back(j);
			seenItems.insert(it->Name);
		}

		auto str = base64::encode((std::string(("nigatv- ")).append(allJson.dump(-1, '~'/*, true*/))).c_str());
		CopyToClipboard(str);
	}
}