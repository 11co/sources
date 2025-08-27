#pragma once
#include <Windows.h>

namespace Cheat
{
	class Options
	{
	public:
		struct LegitBot
		{
			struct AimBot
			{
				bool Enabled;
				int KeyBind = 0;
				bool TargetNPC;
				bool VisibleCheck;
				int HitBox = 0;
				int MaxDistance = 600;
				int Fov = 90;
				int SmoothHorizontal = 80;
				int SmoothVertical = 80;
				bool RageMode;
			}AimBot;
			struct TriggerBot
			{
				bool Enabled;
				int KeyBind = 0;
				bool ShotNPC;
				int Fov = 90;
				bool VisibleCheck;
				int MaxDistance = 250;
				int ReactionTime;
				bool RageMode;
			}Trigger;
			struct SilentAim
			{
				bool Enabled;
				int Fov = 30;
				int KeyBind = 0;
				bool ShotNPC;
				bool VisibleCheck;
				bool RageMode;
				int MaxDistance = 600;
				int HitBox;
			}SilentAim;
			struct MagicBullet
			{
				bool Enabled;
			}MagicBullet;
		}LegitBot;
		struct Visuals
		{
			struct ESP
			{
				struct Players
				{
					int KeyBind = 0;
					bool Enabled = true;
					bool ShowLocalPlayer = false;
					bool ShowNPCs;
					bool VisibleOnly = false;
					int RenderDistance = 500;
					bool FilledBox = false;
					float FilledBoxColor[4] = { 0.f, 1.f, 0.f, 0.33f };
					bool Box = false;
					float BoxColor[4] = { 0.f, 1.f, 0.f, 1.f };
					bool Skeleton = false;
					bool Head = false;
					float HeadColor[4] = { 0.f, 1.f, 0.f, 0.f };
					float SkeletonColor[4] = { 0.f, 1.f, 0.f, 1.f };
					bool Name = true;
					float NameColor[4] = { 0.f, 1.f, 0.f, 1.f };
					bool HealthBar = true;
					int players_healthbar;
					float HealthBarColor[4] = { 0.f, 1.f, 0.f, 1.f };
					bool ArmorBar;
					float ArmorBarColor[4] = { 0.f, 1.f, 0.f, 1.f };
					bool WeaponName;
					float WeaponNameColor[4] = { 0.f, 1.f, 0.f, 1.f };
					bool Distance;
					float DistanceColor[4] = { 0.f, 1.f, 0.f, 1.f };
					bool SnapLines;
					float SnaplinesColor[4] = { 0.f, 1.f, 0.f, 1.f };
					bool Weapon_Misc = true;
				}Players;

				struct Vehicles
				{
					bool Enabled;
					bool IgnoreOccupiedVehicles;
					bool Marker;
					bool Distance;
					bool Name;
					float Color[4] = { 0.f, 1.f, 0.f, 1.f };
				}Vehicles;
			}ESP;
		}Visuals;
		struct Misc
		{
			struct Screen
			{
				bool ShowTriggerFov;
				float TriggerFovColor[4] = { 1.f, 1.f, 1.f, 1.f };
				bool ShowAimbotFov;
				float AimbotFovColor[4] = { 1.f, 1.f, 1.f, 1.f };
				bool ShowSilentAimFov;
				float SilentFovColor[4] = { 1.f, 1.f, 1.f, 1.f };
				float PartColor[4] = { 0.23f, 0.27f, 0.66f, 1.f };
				float FriendColor[4] = { 0.f, 0.f, 1.f, 1.f };
			}Screen;
			struct Exploits
			{
				struct LocalPlayer
				{
					bool Noclip;
					bool InvisibleNC;
					bool invisible;
					int NoclipBind;
					int NoclipSpeed;
					bool shrink;
					bool superjump;
					bool infinitestamina;
					bool antihs;
					bool nocollision;
					bool noragdoll;
					bool speed;
					float speed_value = 1.0f;
					bool custom_fov;
					float fov_value;
					int godbind = 0;
					int unlockbind = 0;
					int health_ammount;
					bool Start_Health;
					bool God;
					bool usegodmodebind;
					int KeyBind = 0;
				}LocalPlayer;

				struct Weapon
				{
					bool infiniteammo;
					bool customspread;
					bool customrecoil;
					bool fastreload;
					float customspreadvalue;
					float customrecoilvalue;

				}Weapon;

				struct Vehicle
				{
					bool b_Vehicle;
					float v_Boost = 1.f;
					float v_Traction = 1.f;
				} m_Vehicle;
			}Exploits;
		}Misc;
		struct General
		{
			bool ShutDown = false;
			int PanicKey = 0;
			int MenuKey = VK_INSERT;
			bool CaptureBypass = true;
			int ThreadDelay = 0;
		}General;
	};
}

inline Cheat::Options g_Options;