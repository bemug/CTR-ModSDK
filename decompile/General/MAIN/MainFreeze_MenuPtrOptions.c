#include <common.h>

void DECOMP_MainFreeze_MenuPtrOptions(struct MenuBox* mb)
{
	short sVar1;
	char bVar2;
	short sVar3;
	short sVar4;
	char cVar5;
	u_short uVar6;
	int iVar7;
	short sVar8;
	short *psVar9;
	int iVar10;
	char **volumeModeString;
	char **dualshockVibrateString;
	u_short areThereRacingWheels;
	int selectedRow;
	int iVar12;
	int i;
	u_int uVar13;
	int iVar14;

	u_short uVar15;
	u_short local_b0 [4];
	u_short local_a8 [4];
	u_short local_a0 [4];

	// used for the volume sliders
	RECT volumeSliderBar;
	RECT volumeSliderBarOutline;
	short volumeSliderTriangle [8];

	// extra menubox details
	RECT glowingcursor;
	RECT titleSeparatorLine;
	RECT menuBoxBG;
	
	short local_70;
	u_short local_68;
	u_short local_60;
	u_short numRacingWheels;
	u_short numAnalogGamepads;
	u_short gamepadSlotBufferMeta1;
	short local_38;
	int local_30;
	
	local_70 = 0;
	numRacingWheels = 0;
	gamepadSlotBufferMeta1 = (u_short)(sdata->gGamepads->slotBuffer[0].controllerData == (PAD_ID_MULTITAP << 4)) << 1;
	MainFreeze_SafeAdvDestroy();
	iVar12 = 0;
	numAnalogGamepads = 0;
	if (sdata->boolOpenWheelConfig != 0)
	{
		MainFreeze_ConfigSetupEntry();
		return;
	}
	// For if you are not in racing wheel configuration
	// Since you did not hit "return", you will continue with the rest of the Options menu
	i = 0;
	if (sdata->gGT->numPlyrCurrGame != 0)
	{
		iVar7 = 0;
		do
		{
			psVar9 = sdata->gGamepads->gamepad[iVar7 >> 0x10].ptrControllerPacket;
			if (((psVar9 == (short *)0x0) || (*(char *)psVar9 != 0)) || ((*(char *)((int)psVar9 + 1) != -0x1d && (*(char *)((int)psVar9 + 1) != '#'))))
			{
				uVar13 = (u_int)numRacingWheels;
				numRacingWheels = numRacingWheels + 1;
				*(short *)((int)local_a8 + ((int)(uVar13 << 0x10) >> 0xf)) = (short)i;
				*(u_short *)((int)local_a0 + ((i << 0x10) >> 0xf)) = 0;
			}
			else
			{
				uVar13 = (u_int)numAnalogGamepads;
				numAnalogGamepads = numAnalogGamepads + 1;
				*(short *)((int)local_b0 + ((int)(uVar13 << 0x10) >> 0xf)) = (short)i;
				local_a0[iVar7 >> 0x10] = 1;
			}
			i = i + 1;
			iVar7 = i * 0x10000;
		} while (i * 0x10000 >> 0x10 < (int)(u_int)sdata->gGT->numPlyrCurrGame);
	}
	// 0 for no racing wheels
	// 1 for racing wheels
	areThereRacingWheels = 0;
	if (numRacingWheels != 0)
	{
		areThereRacingWheels = (u_short)(numAnalogGamepads != 0);
	}
	sVar8 = (4 - areThereRacingWheels) - (u_short)sdata->gGT->numPlyrCurrGame;
	areThereRacingWheels = sVar8 * 10;
	if (numRacingWheels == 0)
	{
		local_60 = 0;
	}
	else
	{
		local_60 = (numRacingWheels + 1) * 10;
	}
	iVar7 = (int)((u_int)areThereRacingWheels << 0x10) >> 0x11;
	data.Options_HighlightBar[8].posY = sVar8 * -10 + 0x77;
	i = 0;
	if (0 < (short)numRacingWheels)
	{
		iVar10 = 0;
		do
		{
			data.Options_HighlightBar[(iVar10 >> 0x10) + 4].posY = (short)((u_int)iVar10 >> 0x10) * 10 + 0x4f;
			i = i + 1;
			iVar10 = i * 0x10000;
		} while (i * 0x10000 >> 0x10 < (int)(short)numRacingWheels);
	}
	iVar10 = (u_int)numAnalogGamepads << 0x10;
	i = 0;
	if (0 < iVar10)
	{
		do
		{
			uVar6 = 0;
			sVar8 = (short)i;
			if ((short)numRacingWheels != 0)
			{
				uVar6 = (u_short)(iVar10 != 0);
			}
			i = i + 1;
			data.Options_HighlightBar[(int)(short)numRacingWheels + sVar8 + 4].posY = (sVar8 + numRacingWheels + uVar6) * 10 + 0x4f;
			iVar10 = (u_int)numAnalogGamepads << 0x10;
		} while (i * 0x10000 < iVar10);
	}
	uVar6 = mb->drawStyle & 0xfeff;
	mb->drawStyle = uVar6;
	if (2 < sdata->gGT->numPlyrCurrGame)
	{
		mb->drawStyle = uVar6 | 0x100;
	}
	local_68 = areThereRacingWheels;
	if ((sdata->AnyPlayerTap & BTN_UP) == 0)
	{
		if ((sdata->AnyPlayerTap & BTN_DOWN) == 0)
		{
			// Do the same for all 3 sliders in Options menu
			// 0: FX slider
			// 1: Music slider
			// 2: Voice slider
			switch(mb->rowSelected)
			{
			case 0:
			case 1:
			case 2:
				selectedRow = (int)mb->rowSelected;
				OptionsMenu_TestSound(selectedRow, 1);
				if ((sdata->AnyPlayerHold & 4) == 0)
				{
					if ((sdata->AnyPlayerHold & 8) != 0)
					{
						// get value of volume slider
						uVar6 = howl_VolumeGet(selectedRow);
						// add to the slider
						uVar6 = (uVar6 & 0xff) + 4;
						// set slider maximum value to 0xFF
						if (0xff < uVar6)
						{
							uVar6 = 0xff;
						}
						howl_VolumeSet(selectedRow, (char)uVar6);
					}
				}
				else
				{
					uVar6 = howl_VolumeGet(selectedRow);
					i = (uVar6 & 0xff) - 4;
					if (i < 0)
					{
						i = 0;
					}
					howl_VolumeSet(selectedRow, i);
				}
				break;
			case 3:
				OptionsMenu_TestSound(0, 0);
				if (sdata->AnyPlayerTap & (BTN_CIRCLE | BTN_CROSS_one))
				{
					OtherFX_Play(1, 1);
					cVar5 = howl_ModeGet();
					howl_ModeSet(cVar5 == 0);
				}
				break;
			case 4:
			case 5:
			case 6:
			case 7:
				OptionsMenu_TestSound(0, 0);
				if (sdata->AnyPlayerTap & (BTN_CIRCLE | BTN_CROSS_one))
				{
					uVar6 = mb->rowSelected;
					OtherFX_Play(1, 1);
					i = (int)((uVar6 - 4) * 0x10000) >> 0x10;
					// if the row you selected is for configuring a racing wheel gamepad
					if (i < (short)numRacingWheels)
					{
						sdata->gGT->gameMode1 = sdata->gGT->gameMode1 ^ data.gGT_gameMode1_Vibration_PerPlayer[(short)local_a8[i]];
					}
					else
					{
						sdata->gamepad_ID_ThatOpenedRaceWheelConfig = local_b0[i - (short)numRacingWheels];
						sdata->boolOpenWheelConfig = 1;
						sdata->raceWheelConfigPageIndex = 0;
					}
				}
				break;
			case 8:
				OptionsMenu_TestSound(0, 0);
				if (sdata->AnyPlayerTap & (BTN_CIRCLE | BTN_CROSS_one))
				{
					OtherFX_Play(1, 1);
					local_70 = 1;
				}
			}
			goto switchD_80038f90_caseD_9;
		}
		OtherFX_Play(0, 1);
		sVar8 = mb->rowSelected + 1;
		mb->rowSelected = sVar8;
		if (8 < sVar8)
		{
			mb->rowSelected = 0;
			goto switchD_80038f90_caseD_9;
		}
		if ((int)sVar8 < (int)(sdata->gGT->numPlyrCurrGame + 4)) goto switchD_80038f90_caseD_9;
	}
	else
	{
		OtherFX_Play(0, 1);
		sVar8 = mb->rowSelected + -1;
		mb->rowSelected = sVar8;
		if (-1 < sVar8)
		{
			if (sVar8 == 7)
			{
				mb->rowSelected = sdata->gGT->numPlyrCurrGame + 3;
			}
			goto switchD_80038f90_caseD_9;
		}
	}
	mb->rowSelected = 8;
switchD_80038f90_caseD_9:
	uVar13 = 0;
	i = 0;
	do
	{
		i = DecalFont_GetLineWidth(sdata->lngStrings[*(short *)((int)data.Options_StringIDs_Audio + (i >> 0xf))], 2);
		if (iVar12 << 0x10 < i << 0x10)
		{
			iVar12 = i;
		}
		uVar13 = uVar13 + 1;
		i = uVar13 * 0x10000;
	} while ((uVar13 & 0xffff) < 3);
	iVar10 = 0;
	
	// "OPTIONS"
	DecalFont_DrawLine(sdata->lngStrings[324], 0x100, (short)((u_int)((iVar7 + 0x1a) * 0x10000) >> 0x10), FONT_BIG, (JUSTIFY_CENTER | ORANGE));

	i = 0x17c - (iVar12 + 0x1e);
	local_38 = (short)i;
	local_30 = (i * 0x10000 >> 0x10) + -5;
	i = 0;
	do
	{
		i = i >> 0x10;
		uVar6 = howl_VolumeGet(i);
		iVar14 = (uVar6 & 0xff) * local_30;
		sVar4 = (short)areThereRacingWheels >> 1;
		sVar8 = sVar4 + (short)(i * 10);
		if (iVar14 < 0)
		{
			iVar14 = iVar14 + 0xff;
		}
		sVar3 = (short)(iVar12 + 0x1e);
		sVar1 = sVar3 + (short)((u_int)iVar14 >> 8) + 0x38;
		volumeSliderBar.x = sVar1 + 1;
		volumeSliderBar.y = sVar8 + 0x30;
		volumeSliderBar.w = 3;
		volumeSliderBar.h = 10;
		CTR_Box_DrawSolidBox(&volumeSliderBar, (u_int *)(data.Options_VolumeSlider_Colors + 0xc), (u_long *)(sdata->gGT->backBuffer->otMem).startPlusFour, &sdata->gGT->backBuffer->primMem);
		volumeSliderBarOutline.y = sVar8 + 0x2f;
		volumeSliderBarOutline.w = 5;
		volumeSliderBarOutline.h = 0xc;
		volumeSliderBarOutline.x = sVar1;
		CTR_Box_DrawSolidBox(&volumeSliderBarOutline, (u_int *)(data.Options_VolumeSlider_Colors + 0x10), (u_long *)(sdata->gGT->backBuffer->otMem).startPlusFour, &sdata->gGT->backBuffer->primMem);
		volumeSliderTriangle[0] = sVar3 + 0x38;
		volumeSliderTriangle[1] = sVar8 + 0x3a;
		volumeSliderTriangle[2] = sVar3 + local_38 + 0x38;
		volumeSliderTriangle[3] = sVar8 + 0x30;
		volumeSliderTriangle[4] = volumeSliderTriangle[2];
		volumeSliderTriangle[5] = volumeSliderTriangle[1];
		MENUBOX_DrawRwdTriangle(volumeSliderTriangle, data.Options_VolumeSlider_Colors, (u_long *)(sdata->gGT->backBuffer->otMem).startPlusFour, &sdata->gGT->backBuffer->primMem);
		
		// "FX:" "MUSIC:" "VOICE:"
		DecalFont_DrawLine(sdata->lngStrings[data.Options_StringIDs_Audio[i]], 0x4c, (short)((u_int)((i * 10 + iVar7 + 0x32) * 0x10000) >> 0x10), 2, ORANGE);

		iVar10 = iVar10 + 1;
		i = iVar10 * 0x10000;
	} while (iVar10 * 0x10000 >> 0x10 < 3);

	// "MODE:"
	DecalFont_DrawLine(sdata->lngStrings[332], 0x4c, (short)((u_int)((iVar7 + 0x50) * 0x10000) >> 0x10), FONT_SMALL, ORANGE);

	cVar5 = howl_ModeGet();
	if (cVar5 == '\0')
	{
		// "MONO"
		volumeModeString = &sdata->lngStrings[333];
	}
	else
	{
		// "STEREO"
		volumeModeString = &sdata->lngStrings[334];
	}
	DecalFont_DrawLine(*volumeModeString, 0x1b4, (short)((u_int)((iVar7 + 0x50) * 0x10000) >> 0x10), FONT_SMALL, (JUSTIFY_RIGHT | WHITE));

	areThereRacingWheels = numRacingWheels;
	if (numRacingWheels != 0)
	{
		// "DUAL SHOCK:"
		DecalFont_DrawLine(sdata->lngStrings[330], 0x4c, (short)((u_int)((iVar7 + 0x5a) * 0x10000) >> 0x10), FONT_SMALL, ORANGE);

		i = DecalFont_GetLineWidth(sdata->lngStrings[data.Options_StringIDs_Gamepads[2]], 2);
		iVar10 = DecalFont_GetLineWidth(sdata->lngStrings[326], 2);
		iVar12 = DecalFont_GetLineWidth(sdata->lngStrings[325], 2);
		iVar14 = 0;
		if (iVar12 << 0x10 < iVar10 << 0x10)
		{
			iVar12 = iVar10;
		}
		iVar12 = (i + iVar12 + 10) * 0x10000;
		iVar12 = 0x100 - ((iVar12 >> 0x10) - (iVar12 >> 0x1f) >> 1);
		if (0 < (short)areThereRacingWheels)
		{
			iVar10 = 0;
			do
			{
				bVar2 = false;
				areThereRacingWheels = *(u_short *)((int)local_a8 + (iVar10 >> 0xf));
				uVar13 = (u_int)areThereRacingWheels;
				psVar9 = sdata->gGamepads->gamepad[(short)areThereRacingWheels].ptrControllerPacket;
				if ((psVar9 == (short *)0x0) || (*(char *)psVar9 != '\0'))
				{
					bVar2 = true;
				}
				if (bVar2)
				{
					uVar15 = GRAY;
				}
				else
				{
					uVar15 = ORANGE;
				}
				// "CONTROLLER 1", "CONTROLLER 2", "CONTROLLER 1A", "CONTROLLER 1B", "CONTROLLER 1C", "CONTROLLER 1D"
				DecalFont_DrawLine
				(
					sdata->lngStrings[*(short *)((int)data.Options_StringIDs_Gamepads + ((int)((uVar13 + gamepadSlotBufferMeta1) * 0x10000) >> 0xf))],
					(short)((u_int)(iVar12 * 0x10000) >> 0x10),
					(short)((u_int)(((short)iVar14 * 10 + iVar7 + 100) * 0x10000) >> 0x10),
					FONT_SMALL, uVar15
				);
				if ((sdata->gGT->gameMode1 & *(u_int *)((int)data.gGT_gameMode1_Vibration_PerPlayer + ((int)(uVar13 << 0x10) >> 0xe))) == 0)
				{
					// "VIBRATE ON"
					dualshockVibrateString = &sdata->lngStrings[325];
				}
				else
				{
					// "VIBRATE OFF"
					dualshockVibrateString = &sdata->lngStrings[326];
				}
				uVar15 = GRAY;
				if ((!bVar2) && (uVar15 = RED, (sdata->gGT->gameMode1 & *(u_int *)((int)data.gGT_gameMode1_Vibration_PerPlayer + ((int)(uVar13 << 0x10) >> 0xe))) == 0))
				{
					uVar15 = WHITE;
				}
				DecalFont_DrawLine
				(
					*dualshockVibrateString,
					(short)((u_int)((iVar12 + i + 10) * 0x10000) >> 0x10),
					(short)((u_int)(((short)iVar14 * 10 + iVar7 + 100) * 0x10000) >> 0x10),
					FONT_SMALL, uVar15
				);
				iVar14 = iVar14 + 1;
				iVar10 = iVar14 * 0x10000;
			} while (iVar14 * 0x10000 < (int)((u_int)numRacingWheels << 0x10));
		}
	}
	iVar12 = (int)(short)numAnalogGamepads;
	if (iVar12 != 0)
	{
		i = 0;
		DecalFont_DrawLine(sdata->lngStrings[336], 0x4c, (short)(((u_int)local_60 + iVar7 + 0x5a) * 0x10000 >> 0x10), FONT_SMALL, ORANGE);
		if (0 < iVar12)
		{
			do
			{
				DecalFont_DrawLine
				(
					sdata->lngStrings[*(short *)((int)data.Options_StringIDs_Gamepads + ((int)(((u_int)local_b0[(short)i] + (u_int)gamepadSlotBufferMeta1) * 0x10000) >> 0xf))],
					0x100,
					(short)((iVar7 + (u_int)local_60 + (short)i * 10 + 100) * 0x10000 >> 0x10),
					FONT_SMALL, (JUSTIFY_CENTER | ORANGE)
				);
				i = i + 1;
			} while (i * 0x10000 >> 0x10 < iVar12);
		}
	}
	// "EXIT"
	DecalFont_DrawLine(sdata->lngStrings[331], 0x4c, (short)(((iVar7 + 0x8c) - (u_int)local_68) * 0x10000 >> 0x10), FONT_SMALL, ORANGE);

	glowingcursor.x = 0x4a;
	glowingcursor.w = 0x16c;
	glowingcursor.y = data.Options_HighlightBar[mb->rowSelected].posY + sVar4 + 0x14;
	glowingcursor.h = data.Options_HighlightBar[mb->rowSelected].sizeY;
	CTR_Box_DrawClearBox(&glowingcursor, &sdata->menuRowHighlight_Normal, TRANS_50_DECAL, (u_long *)(sdata->gGT->backBuffer->otMem).startPlusFour, &sdata->gGT->backBuffer->primMem);

	titleSeparatorLine.x = 66;
	titleSeparatorLine.y = sVar4 + 43;
	titleSeparatorLine.w = 380;
	titleSeparatorLine.h = 2;
	MENUBOX_DrawOuterRect_Edge(&titleSeparatorLine, (u_int)&sdata->battleSetup_Color_UI_1, 0x20, (u_long *)(sdata->gGT->backBuffer->otMem).startPlusFour);

	menuBoxBG.x = 0x38;
	menuBoxBG.w = 400;
	menuBoxBG.h = 0x87 - local_68;
	menuBoxBG.y = sVar4 + 0x14;
	MENUBOX_DrawInnerRect(&menuBoxBG, 4, (u_long *)(sdata->gGT->backBuffer->otMem).startPlusFour);

	if ((local_70 != 0) || ((sdata->AnyPlayerTap & (BTN_TRIANGLE | BTN_START | BTN_SQUARE_one)) != 0))
	{
		OtherFX_Play(1, 1);
		OptionsMenu_TestSound(0, 0);
		MENUBOX_ClearInput();
		sdata->ptrDesiredMenuBox = MainFreeze_GetMenuBox();
	}
	return;
}
