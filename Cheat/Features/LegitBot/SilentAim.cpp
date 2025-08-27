#include "SilentAim.hpp"
#include "../../Options.hpp"

namespace Cheat {

    constexpr int HEAD_INDEX = 0;
    constexpr int NECK_INDEX = 1;
    constexpr int CHEST_INDEX = 2;


    void RestoreSilent()
    {
        std::vector<uint8_t> rewriteTable =
        {
            0xF3, 0x41, 0x0F, 0x10, 0x19,
            0xF3, 0x41, 0x0F, 0x10, 0x41, 0x04,
            0xF3, 0x41, 0x0F, 0x10, 0x51, 0x08
        };

        FrameWork::Memory::WriteProcessMemoryImpl(g_Fivem.GetHandleBulletAddress(), rewriteTable.data(), rewriteTable.size());

        std::vector<uint8_t> angleRewriteTable =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00
        };

        FrameWork::Memory::WriteProcessMemoryImpl(g_Fivem.GetModuleBase() + 0x34E, angleRewriteTable.data(), angleRewriteTable.size());
    }


    void ApplySilent(Vector3D endBulletPos)
    {
        static const uint64_t handleBulletAddress = g_Fivem.GetHandleBulletAddress();
        static const uint64_t allocPtr = g_Fivem.GetModuleBase() + 0x34E;

        auto calculateRelativeOffset = [](uint64_t currentAddress, uint64_t targetAddress, int offset = 5) -> uint32_t {
            return static_cast<uint32_t>(targetAddress - (currentAddress + offset));
            };

        union
        {
            float f;
            uint32_t i;
        } endPosX, endPosY, endPosZ;

        endPosX.f = endBulletPos.x;
        endPosY.f = endBulletPos.y;
        endPosZ.f = endBulletPos.z;

        {
            std::vector<uint8_t> rewriteTable = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

            uint32_t jmpOffset = calculateRelativeOffset(handleBulletAddress, allocPtr);
            std::memcpy(rewriteTable.data() + 1, &jmpOffset, sizeof(jmpOffset));

            FrameWork::Memory::WriteProcessMemoryImpl(handleBulletAddress, rewriteTable.data(), rewriteTable.size());
        }


        {
            uintptr_t currentAddress = static_cast<uintptr_t>(allocPtr);
            uintptr_t targetAddress = static_cast<uintptr_t>(handleBulletAddress);
            uint32_t jmpOffset = calculateRelativeOffset(currentAddress, targetAddress, 28);

            std::vector<uint8_t> rewriteTable =
            {
                0x41, 0xC7, 0x01, static_cast<uint8_t>(endPosX.i), static_cast<uint8_t>(endPosX.i >> 8), static_cast<uint8_t>(endPosX.i >> 16), static_cast<uint8_t>(endPosX.i >> 24),
                0x41, 0xC7, 0x41, 0x04, static_cast<uint8_t>(endPosY.i), static_cast<uint8_t>(endPosY.i >> 8), static_cast<uint8_t>(endPosY.i >> 16), static_cast<uint8_t>(endPosY.i >> 24),
                0x41, 0xC7, 0x41, 0x08, static_cast<uint8_t>(endPosZ.i), static_cast<uint8_t>(endPosZ.i >> 8), static_cast<uint8_t>(endPosZ.i >> 16), static_cast<uint8_t>(endPosZ.i >> 24),
                0xF3, 0x41, 0x0F, 0x10, 0x19,
                0xE9, 0x00, 0x00, 0x00, 0x00
            };

            std::memcpy(rewriteTable.data() + 29, &jmpOffset, sizeof(jmpOffset));

            FrameWork::Memory::WriteProcessMemoryImpl(allocPtr, rewriteTable.data(), rewriteTable.size());
        }
    }


    void SilentAim::RunThread()
    {
        while (!g_Options.General.ShutDown)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1 + g_Options.General.ThreadDelay));

            if (!g_Options.LegitBot.SilentAim.Enabled) {
                continue;
            }

            auto localPlayer = g_Fivem.GetLocalPlayerInfo();
            if (!localPlayer.Ped) {
                continue;
            }

            static bool silentApplied = false;
            Entity closestEntity;
            bool entityFound = g_Fivem.FindClosestEntity(
                g_Options.LegitBot.SilentAim.Fov,
                g_Options.LegitBot.SilentAim.MaxDistance,
                g_Options.LegitBot.SilentAim.ShotNPC,
                &closestEntity);

            if (entityFound) {
                if (closestEntity.StaticInfo.IsFriend ||
                    (g_Options.LegitBot.AimBot.VisibleCheck && !closestEntity.Visible) ||
                    !GetAsyncKeyState(g_Options.LegitBot.SilentAim.KeyBind)) {
                    if (silentApplied) {
                        RestoreSilent();
                        silentApplied = false;
                    }
                    continue;
                }

                Vector3D bonePos;
                switch (g_Options.LegitBot.SilentAim.HitBox) {
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

                ApplySilent(bonePos);
                silentApplied = true;
            }
            else {
                if (silentApplied) {
                    RestoreSilent();
                    silentApplied = false;
                }
            }
        }
    }
}