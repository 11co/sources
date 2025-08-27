#include "AimBot.hpp"
#include "../../Options.hpp"

namespace Cheat
{
    constexpr int HEAD_INDEX = 0;
    constexpr int NECK_INDEX = 1;
    constexpr int CHEST_INDEX = 2;

    void AimBot::RunThread()
    {
        while (true)
        {
            if (g_Options.General.ShutDown) {
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));

            if (!g_Options.LegitBot.AimBot.Enabled || !g_Fivem.GetLocalPlayerInfo().Ped) {
                continue;
            }

            Entity closestEntity;
            if (!g_Fivem.FindClosestEntity(
                g_Options.LegitBot.AimBot.Fov,
                g_Options.LegitBot.AimBot.MaxDistance,
                g_Options.LegitBot.AimBot.TargetNPC,
                &closestEntity)) {
                continue;
            }

            if (!GetAsyncKeyState(g_Options.LegitBot.AimBot.KeyBind) ||
                closestEntity.StaticInfo.IsFriend ||
                (g_Options.LegitBot.AimBot.VisibleCheck && !closestEntity.Visible)) {
                continue;
            }

            Vector3D bonePos;
            switch (g_Options.LegitBot.AimBot.HitBox) {
            case HEAD_INDEX:
                bonePos = g_Fivem.GetBonePosVec3(closestEntity, SKEL_Head);
                break;
            case NECK_INDEX:
                bonePos = g_Fivem.GetBonePosVec3(closestEntity, SKEL_Neck_1);
                break;
            case CHEST_INDEX:
                bonePos = g_Fivem.GetBonePosVec3(closestEntity, SKEL_Spine3);
                break;
            default:
                continue;
            }

            g_Fivem.ProcessCameraMovement(
                bonePos,
                g_Options.LegitBot.AimBot.SmoothHorizontal,
                g_Options.LegitBot.AimBot.SmoothVertical);
        }
    }
}