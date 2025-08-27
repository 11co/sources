#include "Cheat.hpp"
#include "FivemSDK/Fivem.hpp"
#include <thread>
#include <FrameWork/FrameWork.hpp>
#include <chrono>

namespace Cheat
{
	
	void Initialize()
	{
		while (!g_Fivem.IsInitialized())
		{
			g_Fivem.Intialize();

			if (!g_Fivem.IsInitialized())
				std::this_thread::sleep_for(std::chrono::seconds(5));
		}

		FrameWork::Overlay::Setup(g_Fivem.GetPid());
		FrameWork::Overlay::Initialize();

		std::thread([&]() { TriggerBot::RunThread(); }).detach();
		std::thread([&]() { AimBot::RunThread(); }).detach();
		std::thread([&]() { SilentAim::RunThread(); }).detach();
		std::thread([&]() { Exploits::RunThread(); }).detach();
		std::thread([&]() { MagicBullet::RunThread(); }).detach();

		if (FrameWork::Overlay::IsInitialized())
		{
			FrameWork::Interface Interface(FrameWork::Overlay::GetOverlayWindow(), FrameWork::Overlay::GetTargetWindow(), FrameWork::Overlay::dxGetDevice(), FrameWork::Overlay::dxGetDeviceContext());
			Interface.UpdateStyle();
			FrameWork::Overlay::SetupWindowProcHook(std::bind(&FrameWork::Interface::WindowProc, &Interface, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));

			MSG Message;
			ZeroMemory(&Message, sizeof(Message));
			while (Message.message != WM_QUIT)
			{
				if (PeekMessage(&Message, FrameWork::Overlay::GetOverlayWindow(), NULL, NULL, PM_REMOVE))
				{
					TranslateMessage(&Message);
					DispatchMessage(&Message);
				}

				ImGui::GetIO().MouseDrawCursor = Interface.GetMenuOpen();

				g_Fivem.UpdateEntities();
				g_Fivem.UpdateVehicles();

				if (Interface.ResizeHeight != 0 || Interface.ResizeWidht != 0)
				{
					FrameWork::Overlay::dxCleanupRenderTarget();
					FrameWork::Overlay::dxGetSwapChain()->ResizeBuffers(0, Interface.ResizeWidht, Interface.ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
					Interface.ResizeHeight = Interface.ResizeWidht = 0;
					FrameWork::Overlay::dxCreateRenderTarget();
				}

				Interface.HandleMenuKey();
				FrameWork::Overlay::UpdateWindowPos();

				static bool CaptureBypassOn = false;
				if (g_Options.General.CaptureBypass != CaptureBypassOn)
				{
					CaptureBypassOn = g_Options.General.CaptureBypass;
					SafeCall(SetWindowDisplayAffinity)(FrameWork::Overlay::GetOverlayWindow(), CaptureBypassOn ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
				}

				ImGui_ImplDX11_NewFrame();
				ImGui_ImplWin32_NewFrame();
				ImGui::NewFrame();
				{
					ImColor Color =
						ImColor(g_Options.Misc.Screen.AimbotFovColor[0], g_Options.Misc.Screen.AimbotFovColor[1], g_Options.Misc.Screen.AimbotFovColor[2], g_Options.Misc.Screen.AimbotFovColor[3]);

					ImColor Color2 =
						ImColor(g_Options.Misc.Screen.SilentFovColor[0], g_Options.Misc.Screen.SilentFovColor[1], g_Options.Misc.Screen.SilentFovColor[2], g_Options.Misc.Screen.SilentFovColor[3]);

					ImColor Color3 =
						ImColor(g_Options.Misc.Screen.TriggerFovColor[0], g_Options.Misc.Screen.TriggerFovColor[1], g_Options.Misc.Screen.TriggerFovColor[2], g_Options.Misc.Screen.TriggerFovColor[3]);

					if (g_Options.Misc.Screen.ShowAimbotFov)
						ImGui::GetBackgroundDrawList()->AddCircle(ImVec2(ImGui::GetIO().DisplaySize.x / 2, ImGui::GetIO().DisplaySize.y / 2), g_Options.LegitBot.AimBot.Fov, Color, 360);

					if (g_Options.Misc.Screen.ShowSilentAimFov)
						ImGui::GetBackgroundDrawList()->AddCircle(ImVec2(ImGui::GetIO().DisplaySize.x / 2, ImGui::GetIO().DisplaySize.y / 2), g_Options.LegitBot.SilentAim.Fov, Color2, 360);

					if (g_Options.Misc.Screen.ShowTriggerFov)
						ImGui::GetBackgroundDrawList()->AddCircle(ImVec2(ImGui::GetIO().DisplaySize.x / 2, ImGui::GetIO().DisplaySize.y / 2), g_Options.LegitBot.Trigger.Fov, Color3, 360);

					if (g_Options.Visuals.ESP.Vehicles.Enabled)
						ESP::Vehicles();

					if (g_Options.Visuals.ESP.Players.Enabled)
						ESP::Players();

					Interface.RenderGui();
				}
				ImGui::EndFrame();
				ImGui::Render();

				FrameWork::Overlay::dxRefresh();
				ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
				FrameWork::Overlay::dxGetSwapChain()->Present(0, 0);

				if (g_Options.General.ShutDown)
					return;
			}
		}
	}

	void ShutDown()
	{

	}
}