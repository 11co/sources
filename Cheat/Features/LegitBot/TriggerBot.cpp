#include "TriggerBot.hpp"

#include <thread>

#include "../../Options.hpp"

namespace Cheat
{
    void TriggerBot::RunThread()
    {
        while (!g_Options.General.ShutDown)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1 + g_Options.General.ThreadDelay));

            if (!g_Options.LegitBot.Trigger.Enabled)
                continue;

            if (!g_Fivem.GetLocalPlayerInfo().Ped)
                continue;

            static bool Shooting = false;

            bool CanShoot = false;

            Entity closestEntity;
            if (g_Fivem.FindClosestEntity(
                g_Options.LegitBot.Trigger.Fov,
                g_Options.LegitBot.Trigger.MaxDistance,
                g_Options.LegitBot.Trigger.ShotNPC,
                &closestEntity))
            {
                if (closestEntity.StaticInfo.IsFriend || !closestEntity.Visible)
                {
                    continue;
                }

                if (GetAsyncKeyState(g_Options.LegitBot.Trigger.KeyBind))
                {
                    CanShoot = true;
                }
            }

            if (CanShoot && !Shooting)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(g_Options.LegitBot.Trigger.ReactionTime));

                INPUT input = { 0 };
                input.type = INPUT_MOUSE;
                input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
                SafeCall(SendInput)(1, &input, sizeof(INPUT));

                Shooting = true;
            }
            else if (Shooting && !CanShoot)
            {
                INPUT input = { 0 };
                input.type = INPUT_MOUSE;
                input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
                SafeCall(SendInput)(1, &input, sizeof(INPUT));

                Shooting = false;
            }
        }
    }
}