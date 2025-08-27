#include "PlayerESP.hpp"

#include <cmath>

#include "../../FivemSDK/Fivem.hpp"
#include "../../Options.hpp"
#include <optional>
#include <utility>
#include <vector>
#include "ImGui/imgui.h"

struct Position
{
	ImVec2 Pos;
};


namespace Cheat
{
	void ESP::Players()
	{
		if (!g_Fivem.GetLocalPlayerInfo().Ped)
			return;

		for (Entity Current : g_Fivem.GetEntitiyList())
		{
			if (Current.StaticInfo.bIsLocalPlayer && !g_Options.Visuals.ESP.Players.ShowLocalPlayer)
				continue;

			if (Current.StaticInfo.bIsNPC && !g_Options.Visuals.ESP.Players.ShowNPCs)
				continue;

			if (g_Options.Visuals.ESP.Players.VisibleOnly && !Current.Visible)
				continue;

			Vector3D PedCoordinates = Current.Cordinates;

			float Distance = PedCoordinates.DistTo(g_Fivem.GetLocalPlayerInfo().WorldPos);

			if (Distance > g_Options.Visuals.ESP.Players.RenderDistance)
				continue;

			ImVec2 PedLocation = g_Fivem.WorldToScreen(PedCoordinates);

			ImVec2 Head = Current.HeadPos;
			if (!g_Fivem.IsOnScreen(Head))
				continue;

			ImVec2 LeftFoot = g_Fivem.WorldToScreen(g_Fivem.GetBonePosVec3(Current, SKEL_L_Foot));
			if (!g_Fivem.IsOnScreen(LeftFoot))
				continue;

			ImVec2 RightFoot = g_Fivem.WorldToScreen(g_Fivem.GetBonePosVec3(Current, SKEL_R_Foot));
			if (!g_Fivem.IsOnScreen(RightFoot))
				continue;

			float Height = -Head.y;

			if (LeftFoot.y > RightFoot.y)
				Height += LeftFoot.y;
			else
				Height += RightFoot.y;

			float Width = Height / 1.8f;
			float PedCenterY = Head.y + Height / 2.f;
			Height *= 1.2f;

			ImVec2 Padding[4] = { ImVec2(0, 0), ImVec2(0, 0), ImVec2(0, 0), ImVec2(0, 0) };

			if (g_Options.Visuals.ESP.Players.Box)
			{
				ImColor Color = (Current.StaticInfo.IsFriend)
					? ImColor(g_Options.Misc.Screen.FriendColor[0], g_Options.Misc.Screen.FriendColor[1], g_Options.Misc.Screen.FriendColor[2], g_Options.Misc.Screen.FriendColor[3])
					: ImColor(g_Options.Visuals.ESP.Players.BoxColor[0], g_Options.Visuals.ESP.Players.BoxColor[1], g_Options.Visuals.ESP.Players.BoxColor[2], g_Options.Visuals.ESP.Players.BoxColor[3]);

				ImVec2 rectMin = ImVec2(PedLocation.x - Width / 2, PedCenterY - Height / 2.f);
				ImVec2 rectMax = ImVec2(PedLocation.x + Width / 2, PedCenterY + Height / 2.f);

				ImDrawList* drawList = ImGui::GetBackgroundDrawList();
				if (drawList) {
					drawList->AddRect(rectMin, rectMax, ImColor(0, 0, 0), 0, ImDrawFlags_None, 3);
					drawList->AddRect(rectMin, rectMax, Color, 0, ImDrawFlags_None, 2);
				}

				Padding[0].y += 3;
				Padding[1].x += 3;
				Padding[2].y += 3;
				Padding[3].x += 3;
			}

			if (g_Options.Visuals.ESP.Players.FilledBox)
			{
				if (g_Options.Visuals.ESP.Players.Box) {
					ImColor Color = (Current.StaticInfo.IsFriend)
						? ImColor(g_Options.Misc.Screen.FriendColor[0], g_Options.Misc.Screen.FriendColor[1], g_Options.Misc.Screen.FriendColor[2], g_Options.Misc.Screen.FriendColor[3])
						: ImColor(g_Options.Visuals.ESP.Players.FilledBoxColor[0], g_Options.Visuals.ESP.Players.FilledBoxColor[1], g_Options.Visuals.ESP.Players.FilledBoxColor[2], g_Options.Visuals.ESP.Players.FilledBoxColor[3]);

					ImVec2 rectMin = ImVec2(PedLocation.x - Width / 2, PedCenterY - Height / 2.f);
					ImVec2 rectMax = ImVec2(PedLocation.x + Width / 2, PedCenterY + Height / 2.f);

					ImDrawList* drawList = ImGui::GetBackgroundDrawList();
					if (drawList) {
						drawList->AddRectFilled(rectMin, rectMax, Color);
					}

					Padding[0].y += 3;
					Padding[1].x += 3;
					Padding[2].y += 3;
					Padding[3].x += 3;
				}
			}

			if (g_Options.Visuals.ESP.Players.Skeleton)
			{
				ImColor Color = (Current.StaticInfo.IsFriend)
					? ImColor(g_Options.Misc.Screen.FriendColor[0], g_Options.Misc.Screen.FriendColor[1], g_Options.Misc.Screen.FriendColor[2], g_Options.Misc.Screen.FriendColor[3])
					: ImColor(g_Options.Visuals.ESP.Players.SkeletonColor[0], g_Options.Visuals.ESP.Players.SkeletonColor[1], g_Options.Visuals.ESP.Players.SkeletonColor[2], g_Options.Visuals.ESP.Players.SkeletonColor[3]);

				static const std::pair<int, int> bonePairs[] = {
					{SKEL_Pelvis, SKEL_Neck_1}, {SKEL_Neck_1, SKEL_L_Clavicle},
					{SKEL_Neck_1, SKEL_R_Clavicle}, {SKEL_L_Clavicle, SKEL_L_UpperArm},
					{SKEL_R_Clavicle, SKEL_R_UpperArm}, {SKEL_L_UpperArm, SKEL_L_Forearm},
					{SKEL_R_UpperArm, SKEL_R_Forearm}, {SKEL_L_Forearm, SKEL_L_Hand},
					{SKEL_R_Forearm, SKEL_R_Hand}, {SKEL_Pelvis, SKEL_L_Thigh},
					{SKEL_Pelvis, SKEL_R_Thigh}, {SKEL_L_Thigh, SKEL_L_Calf},
					{SKEL_R_Thigh, SKEL_R_Calf}, {SKEL_L_Calf, SKEL_L_Foot},
					{SKEL_R_Calf, SKEL_R_Foot}
				};

				auto GetBoneScreenPos = [&](int boneId) -> std::optional<ImVec2> {
					ImVec2 pos = g_Fivem.WorldToScreen(g_Fivem.GetBonePosVec3(Current, boneId));
					return g_Fivem.IsOnScreen(pos) ? std::optional<ImVec2>{pos} : std::nullopt;
					};

				ImDrawList* drawList = ImGui::GetBackgroundDrawList();
				if (drawList) {
					for (const auto& [boneA, boneB] : bonePairs) {
						auto boneAPos = GetBoneScreenPos(boneA);
						auto boneBPos = GetBoneScreenPos(boneB);

						if (boneAPos && boneBPos) {
							drawList->AddLine(*boneAPos, *boneBPos, Color, 1.f);
						}
					}
				}
			}

			if (g_Options.Visuals.ESP.Players.Head)
			{
				ImColor Color = (Current.StaticInfo.IsFriend)
					? ImColor(g_Options.Misc.Screen.FriendColor[0], g_Options.Misc.Screen.FriendColor[1], g_Options.Misc.Screen.FriendColor[2], g_Options.Misc.Screen.FriendColor[3])
					: ImColor(g_Options.Visuals.ESP.Players.HeadColor[0], g_Options.Visuals.ESP.Players.HeadColor[1], g_Options.Visuals.ESP.Players.HeadColor[2], g_Options.Visuals.ESP.Players.HeadColor[3]);

				auto GetBoneScreenPos = [&](int boneId) -> std::optional<ImVec2> {
					ImVec2 pos = g_Fivem.WorldToScreen(g_Fivem.GetBonePosVec3(Current, boneId));
					return g_Fivem.IsOnScreen(pos) ? std::optional<ImVec2>{pos} : std::nullopt;
					};

				auto headPos = GetBoneScreenPos(SKEL_Head);

				if (headPos) {
					float distance = Current.Cordinates.DistTo(Cheat::g_Fivem.GetLocalPlayerInfo().WorldPos);

					float radius = std::clamp(100.f / distance, 1.5f, 15.0f);

					ImDrawList* drawList = ImGui::GetBackgroundDrawList();
					if (drawList) {
						drawList->AddCircle(*headPos, radius, Color, 16, 1.f);
					}
				}
			}

			if (g_Options.Visuals.ESP.Players.HealthBar)
			{
				switch (g_Options.Visuals.ESP.Players.players_healthbar)
				{
				case 0: // Left
				{
					float Health = Current.StaticInfo.Ped->GetHealth();
					float MaxHealth = Current.StaticInfo.Ped->GetMaxHealth();

					ImColor healthColor = (Health > MaxHealth * 0.66f) ? ImColor(0, 255, 0) : (Health > MaxHealth * 0.33f) ? ImColor(255, 255, 0) : ImColor(255, 0, 0);

					ImVec2 DrawPos = ImVec2(PedLocation.x - Width / 2, PedCenterY - Height / 2) - Padding[3] - ImVec2(6, 0);
					ImVec2 Size = ImVec2(0, Height);
					ImVec2 DrawSize = ImVec2(-2, (Height / MaxHealth) * Health);

					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos - ImVec2(1, 1), DrawPos + Size + ImVec2(1, 1), ImColor(0, 0, 0));
					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos, DrawPos + Size + ImVec2(3, 0), ImColor(0, 0, 0));

					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos + Size, DrawPos + Size - DrawSize, healthColor);

					Padding[3].x += 4;
					break;
				}
				case 1: // Right
				{
					float Health = Current.StaticInfo.Ped->GetHealth();
					float MaxHealth = Current.StaticInfo.Ped->GetMaxHealth();

					ImColor healthColor = (Health > MaxHealth * 0.66f) ? ImColor(0, 255, 0) : (Health > MaxHealth * 0.33f) ? ImColor(255, 255, 0) : ImColor(255, 0, 0);

					ImVec2 DrawPos = ImVec2(PedLocation.x + Width / 2 + 2, PedCenterY - Height / 2);
					ImVec2 Size = ImVec2(4, Height);
					ImVec2 DrawSize = ImVec2(2, (Height / MaxHealth) * Health);

					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos, DrawPos + Size, ImColor(0, 0, 0));

					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos + ImVec2(1, Height - DrawSize.y), DrawPos + ImVec2(3, Height), healthColor);

					Padding[1].x += 6;
					break;
				}

				case 2: // Bottom
				{
					float Health = Current.StaticInfo.Ped->GetHealth();
					float MaxHealth = Current.StaticInfo.Ped->GetMaxHealth();

					ImColor healthColor = (Health > MaxHealth * 0.66f) ? ImColor(0, 255, 0) : (Health > MaxHealth * 0.33f) ? ImColor(255, 255, 0) : ImColor(255, 0, 0);

					ImVec2 DrawPos = ImVec2(PedLocation.x - Width / 2, PedCenterY + Height / 2 + 2) + Padding[2];
					ImVec2 Size = ImVec2(Width, 4);
					ImVec2 DrawSize = ImVec2((Width / MaxHealth) * Health, 2);

					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos, DrawPos + Size, ImColor(0, 0, 0));

					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos + ImVec2(0, 1), DrawPos + ImVec2(DrawSize.x, 3), healthColor);

					Padding[2].y += 6;
					break;
				}

				case 3: // Top
				{
					float Health = Current.StaticInfo.Ped->GetHealth();
					float MaxHealth = Current.StaticInfo.Ped->GetMaxHealth();

					ImColor healthColor = (Health > MaxHealth * 0.66f) ? ImColor(0, 255, 0) : (Health > MaxHealth * 0.33f) ? ImColor(255, 255, 0) : ImColor(255, 0, 0);

					ImVec2 DrawPos = ImVec2(PedLocation.x - Width / 2, PedCenterY - Height / 2 - 6) - Padding[0];
					ImVec2 Size = ImVec2(Width, 4);
					ImVec2 DrawSize = ImVec2((Width / MaxHealth) * Health, 2);

					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos, DrawPos + Size, ImColor(0, 0, 0));

					ImGui::GetBackgroundDrawList()->AddRectFilled(DrawPos + ImVec2(0, 1), DrawPos + ImVec2(DrawSize.x, 3), healthColor);

					Padding[0].y += 6;
					break;
				}
				}
			}
			if (g_Options.Visuals.ESP.Players.ArmorBar)
			{
				ImColor Color = ImColor(g_Options.Visuals.ESP.Players.ArmorBarColor[0],
					g_Options.Visuals.ESP.Players.ArmorBarColor[1],
					g_Options.Visuals.ESP.Players.ArmorBarColor[2],
					g_Options.Visuals.ESP.Players.ArmorBarColor[3]);

				float Armor = Current.StaticInfo.Ped->GetArmor();
				const float MaxArmor = 100.0f;

				if (Armor > 0) {
					ImVec2 DrawPos = ImVec2(PedLocation.x - Width / 2, PedCenterY + Height / 2 + Padding[2].y);
					ImVec2 Size = ImVec2(Width, 2);
					ImVec2 DrawSize = ImVec2((Width / MaxArmor) * Armor, 2);

					ImDrawList* drawList = ImGui::GetBackgroundDrawList();
					if (drawList) {
						drawList->AddRectFilled(DrawPos - ImVec2(1, 1), DrawPos + Size + ImVec2(1, 1), ImColor(0, 0, 0));
						drawList->AddRectFilled(DrawPos, DrawPos + Size, ImColor(0, 0, 0));
						drawList->AddRectFilled(DrawPos, DrawPos + DrawSize, Color);
					}

					Padding[2].y += 3;
				}
			}
			if (g_Options.Visuals.ESP.Players.Name)
			{
				std::string Name = Current.StaticInfo.Name;
				if (Name.empty())
					Name = ("npc");

				ImVec2 TextSize = ImGui::CalcTextSize(Name.c_str());

				ImVec2 DrawPos = ImVec2(PedLocation.x, PedCenterY + Height / 2);
				DrawPos = ImVec2(DrawPos.x - TextSize.x / 2, DrawPos.y + Padding[2].y);
				Padding[2].y += TextSize.y;

				ImGui::PushFont(FrameWork::Assets::InterBold12);

				ImColor Color = ImColor(g_Options.Visuals.ESP.Players.NameColor[0], g_Options.Visuals.ESP.Players.NameColor[1], g_Options.Visuals.ESP.Players.NameColor[2], g_Options.Visuals.ESP.Players.NameColor[3]);

				ImGui::GetBackgroundDrawList()->AddText(DrawPos + ImVec2(1, 1), ImColor(0.f, 0.f, 0.f, g_Options.Visuals.ESP.Players.NameColor[3]), Name.c_str());
				ImGui::GetBackgroundDrawList()->AddText(DrawPos, Color, Name.c_str());

				ImGui::PopFont();
			}
			if (g_Options.Visuals.ESP.Players.WeaponName)
			{
				CWeaponManager* WeaponManager = Current.StaticInfo.Ped->GetWeaponManager();
				if (WeaponManager)
				{
					CWeaponInfo* WeaponInfo = WeaponManager->GetWeaponInfo();
					if (WeaponInfo)
					{
						std::string WeaponName = WeaponInfo->GetWeaponName();
						if (WeaponName.size() > 0)
						{
							ImVec2 TextSize = ImGui::CalcTextSize(WeaponName.c_str());

							ImVec2 DrawPos = ImVec2(PedLocation.x, PedCenterY + Height / 2);
							DrawPos = ImVec2(DrawPos.x - TextSize.x / 2, DrawPos.y + Padding[2].y - 3);
							Padding[2].y += TextSize.y;

							ImColor Color = ImColor(g_Options.Visuals.ESP.Players.WeaponNameColor[0], g_Options.Visuals.ESP.Players.WeaponNameColor[1], g_Options.Visuals.ESP.Players.WeaponNameColor[2], g_Options.Visuals.ESP.Players.WeaponNameColor[3]);

							ImGui::PushFont(FrameWork::Assets::InterBold12);

							ImGui::GetBackgroundDrawList()->AddText(DrawPos + ImVec2(1, 1), ImColor(0.f, 0.f, 0.f, g_Options.Visuals.ESP.Players.WeaponNameColor[3]), WeaponName.c_str());
							ImGui::GetBackgroundDrawList()->AddText(DrawPos, Color, WeaponName.c_str());

							ImGui::PopFont();
						}
					}
				}
			}
			if (g_Options.Visuals.ESP.Players.Distance)
			{
				if (!Current.StaticInfo.bIsLocalPlayer)
				{
					std::string PlayerDistance = std::to_string((int)Distance) + ("m");
					ImVec2 TextSize = ImGui::CalcTextSize(PlayerDistance.c_str());

					ImVec2 DrawPos = ImVec2(PedLocation.x, PedCenterY + Height / 2);

					DrawPos = ImVec2(DrawPos.x - TextSize.x / 2, DrawPos.y + Padding[2].y - 3);
					Padding[2].y += TextSize.y;

					ImColor Color = ImColor(g_Options.Visuals.ESP.Players.DistanceColor[0], g_Options.Visuals.ESP.Players.DistanceColor[1], g_Options.Visuals.ESP.Players.DistanceColor[2], g_Options.Visuals.ESP.Players.DistanceColor[3]);

					ImGui::PushFont(FrameWork::Assets::InterBold12);

					ImGui::GetBackgroundDrawList()->AddText(DrawPos + ImVec2(1, 1), ImColor(0.f, 0.f, 0.f, g_Options.Visuals.ESP.Players.DistanceColor[3]), PlayerDistance.c_str());
					ImGui::GetBackgroundDrawList()->AddText(DrawPos, Color, PlayerDistance.c_str());

					ImGui::PopFont();
				}
			}
			if (g_Options.Visuals.ESP.Players.SnapLines)
			{
				if (!Current.StaticInfo.bIsLocalPlayer) {
					ImColor Color = Current.StaticInfo.IsFriend
						? ImColor(g_Options.Misc.Screen.FriendColor[4], g_Options.Misc.Screen.FriendColor[1], g_Options.Misc.Screen.FriendColor[2], g_Options.Misc.Screen.FriendColor[3])
						: ImColor(g_Options.Visuals.ESP.Players.SnaplinesColor[0], g_Options.Visuals.ESP.Players.SnaplinesColor[1], g_Options.Visuals.ESP.Players.SnaplinesColor[2], g_Options.Visuals.ESP.Players.SnaplinesColor[3]);

					ImDrawList* drawList = ImGui::GetBackgroundDrawList();
					if (drawList) {
						drawList->AddLine(g_Fivem.GetLocalPlayerInfo().ScreenPos, PedLocation, Color);
					}
				}

			}

			if (g_Options.Visuals.ESP.Players.Weapon_Misc)
			{
				CWeaponManager* WeaponManager = Current.StaticInfo.Ped->GetWeaponManager();
				if (WeaponManager)
				{
					CWeaponInfo* WeaponInfo = WeaponManager->GetWeaponInfo();
					if (WeaponInfo)
					{
						if (g_Options.Misc.Exploits.Weapon.customrecoil)
						{
							if (WeaponManager)
							{
								auto weaponinfo = WeaponManager->GetWeaponInfo();

								FrameWork::Memory::WriteMemory<float>((uintptr_t)weaponinfo + 0x2F4, g_Options.Misc.Exploits.Weapon.customrecoilvalue);
							}
						}
						else
						{
							if (WeaponManager)
							{

								auto weaponinfo = WeaponManager->GetWeaponInfo();

								FrameWork::Memory::WriteMemory<float>((uintptr_t)weaponinfo + 0x2F4, 0.5f);
							}

						}
						if (g_Options.Misc.Exploits.Weapon.fastreload)
						{
							if (WeaponManager)
							{
								auto weaponinfo = WeaponManager->GetWeaponInfo();

								FrameWork::Memory::WriteMemory<float>((uintptr_t)weaponinfo + 0x134, 10.f);
							}
						}
						else
						{
							if (WeaponManager)
							{

								auto weaponinfo = WeaponManager->GetWeaponInfo();

								FrameWork::Memory::WriteMemory<float>((uintptr_t)weaponinfo + 0x134, 1.f);
							}

						}
						if (g_Options.Misc.Exploits.Weapon.customspread)
						{
							if (WeaponManager)
							{
								auto weaponinfo = WeaponManager->GetWeaponInfo();

								FrameWork::Memory::WriteMemory<float>((uintptr_t)weaponinfo + 0x84, g_Options.Misc.Exploits.Weapon.customspreadvalue);
							}
						}
						else
						{
							if (WeaponManager)
							{

								auto weaponinfo = WeaponManager->GetWeaponInfo();

								FrameWork::Memory::WriteMemory<float>((uintptr_t)weaponinfo + 0x84, 0.5f);
							}

						}
					}
				}
			}
		}
	}
}