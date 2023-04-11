// MainMenu
struct Title
{
	// 0x0
	struct Thread* t;

	// 0x4
	struct Instance* i[6];

	// 0x1c
	short cameraPosOffset[3];

	// 0x22
	short UnusedPadding;

	// 0x24 -- size of struct
};


// array at 0x800b53b0
struct MainMenu_LevelRow
{
	// 0 - dingo canyon
	// 3 - crash cove
	// etc
	short levID;

	// texture that shows before video plays
	short videoThumbnail;

	// which black+white map draws
	short mapTextureID;

	// 0xFFFF for unlock by default
	// otherwise has a flag for what is needed,
	// 0xFFFE means "only show in 1P mode" (oxide station)
	short unlock;

	// changes which video of level plays
	int videoID;

	// how long video plays before looping
	int videoLength;

	// total struct is 16 bytes large,
	// this structure is complete
};

struct CharacterSelectMeta
{
	// 0x0
	short posX;
	short posY;
	
	// 0x4
	// up, down, left, right
	// must be array, needs enum,
	// see MM_Characters_GetNextDriver,
	// which means MenuRow needs the same
	char indexNext[4];
	
	// 0x8
	short characterID;
	short unlockFlags;
	
	// 0xC -- size
};

struct TransitionMeta
{
	short distX;
	short distY;
	
	// change when each one starts to move
	short headStart;
	
	short currX;
	short currY;
		
	// 0xA -- size
};

// starts at 800ab9f0, overlay region 3
extern struct
{
	// 800ab9f0 (tag given by compiler, meaningless to game)
	// do not compile this "tag" in the struct when we're actually building the overlay
	int overlayTag;
	
	// 800ab9f4
	// just like overlayTag, generated by compiler
	void* jmpPtrs[6];

	// 800aba0c
	// "title"
	char s_title[8];
	
	// 800aba14
	// 0,1,2,3,4,5,6,7
	int characterID_default[2];

	// strings for the player numbers in the character select screen
	// "4"
	char s_4[4];
	// 800aba20
	// "3"
	char s_3[4];
	// "2"
	char s_2[4];
	// 800aba28
	// "1"
	char s_1[4];

	char fillafterrankstrings[0x18];

	// 800aba44
	char s_loaded_ghost_data[20];

	char fillafterloadedghostdatastring[0x30];

	// 800aba88
	// " test.str 1"
	char s_teststr1[12];
	
	// 800aba94
	char fillafterteststr[0x8A50];

	// 800b44e4
	struct MenuRow rows_mainMenu_Basic[7];

	char padding800b450E[2];

	// 800b4510
	struct MenuRow rows_mainMenu_WithScrapbook[8];

	// 800b4540
	struct MenuBox menubox_mainMenu;

	// 800b456c
	struct MenuRow rows_players1P2P[3];
	
	// 800b4580
	struct MenuBox menubox_players1P2P;
	
	// 800b45ac
	struct MenuRow rows_players2P3P4P[4];
	
	// 800b45c4
	struct MenuBox menubox_players2P3P4P;
	
	// 800b45f0
	struct MenuRow rows_difficulty[4];
	
	// 800b4608
	struct MenuBox menubox_difficulty;
	
	// 800b4634
	struct MenuRow rows_raceType[3];
	
	// 800b4648
	struct MenuBox menubox_raceType;
	
	// 800b4670
	struct MenuRow rows_adventure[3];
	
	// 800b4688
	struct MenuBox menubox_adventure;
	
	// 800b46b4
	struct MenuBox menubox_characterSelect;

	// 800b46e0
	struct MenuBox menubox_trackSelect;
	
	// 800b470c
	struct MenuRow rows_cupSelect[5];

	// 800b472c
	struct MenuBox menubox_cupSelect;	
	
	// 800b4758
	struct MenuBox menubox_battleWeapons;
	
	// 800b4784
	struct MenuBox menubox_highScores;
	
	// 800b47b0
	struct MenuBox menubox_scrapbook;
	
	// 800b47dc
	// array of menubox pointers
	struct MenuBox* ptrMenuBoxes[9];
	
	// 800B4800
	struct
	{
		short modelID;
		
		// related to frame, or sound, idk
		short frameIndex_startMoving;
		short unk2;
		
		short boolApplyFlag;
		
	} titleInstances[6];
	
	// 800B4830
	char titleCameraPosRot[0x10];
	
	// 800B4840
	// random stuff related to the title animation,
	// come up with better names later
	char title_OtherStuff[0x84];
	
	// 800b48c4
	struct
	{
		short frameToPlay;
		short soundID;
	} titleSounds[8];
	
	// 800B48E4 (cheats)
	struct
	{
		int numButtons;
		int buttons[10];
		void* funcPtr;
	} cheats[0x16];
	
	// 800B4D04
	int cheatButtonEntry[10];
	
	// 800B4D2C
	short cupDifficultyUnlockFlags[4];
	
	// 800B4D34
	short cupDifficultyLngIndex[4];
	
	// 800B4D3C
	short cupDifficultySpeed[4];
	
	// 800B4D44
	struct
	{
		short posX;
		short posY;
	} characterSelectWindowPos[0xD];
	
	// 800b4d78 - pointer
	void* ptrSelectWindowPos[6];
	
	// 800B4D90
	short windowW[6];
	
	// 800B4D9C
	short windowH[6];
	
	// 800b4da8
	short driverPosZ[6];
	
	// 800b4db4
	short driverPosY[6];
	
	// 800b4dc0
	short textPosArr[6];
	
	// 800b4dcc
	struct CharacterSelectMeta csm_1P2P_limited[0xF];
	
	// 800b4e80
	struct CharacterSelectMeta csm_1P2P[0xF];
	
	// 800b4f34
	struct CharacterSelectMeta csm_3P[0xF];
	
	// 800b4fe8
	struct CharacterSelectMeta csm_4P[0xF];

	// 800b509C
	struct CharacterSelectMeta* ptrCsmArr[6];
	
	// 800b50B4
	// wouldn't need this if icons were stored by order of characterID
	short characterIcon[0x10];
	
	// 0x15 for transition meta array:
	// 14 character icons + title text + 4 kart screens + 2 more?
	
	// 800b50D4
	// 1P/2P mode
	struct TransitionMeta transitionMeta_csm_1P2P[0x15];
	
	// 0x2 byte padding
	short padding800b51A6;
	
	// 3P mode
	// 800b51A8
	struct TransitionMeta transitionMeta_csm_3P[0x15];
	
	// 0x2 byte padding
	short padding800B527A;
	
	// 4P mode
	// 800b527c
	struct TransitionMeta transitionMeta_csm_4P[0x15];
	
	// 0x2 byte padding
	short padding800B534E;
	
	// 800B5350
	struct TransitionMeta* ptr_transitionMeta_csm[4];
	
	// 800B5360
	short csm_instPos[4];
	short csm_instRot[3];
	short moveModels;
	
	// 800B5370
	int unkCharacterWindows;
	
	// 800b5374
	// points to s_1, s_2, s_3, s_4
	int* PlayerNumberStrings[4];
	
	#if 0
	// 800b5384
	// 800b5388
	// 800b538c
	#endif
	char dataUnk[0xC];
	
	// 800b5390
	int characterSelect_NeutralColor;
	
	// 800b5394
	int characterSelect_ChosenColor;
	
	// 800b5398
	char characterSelect_BlueRectColors[0x18];
	
	// 800b53b0
	struct MainMenu_LevelRow arcadeTracks[0x12];
	
	// 800b54d0
	struct MainMenu_LevelRow battleTracks[0x7];
	
	// 800b5540
	// why on earth does it need this many?
	struct TransitionMeta transitionMeta_trackSel[0x11];
	
	short padding800b55EA;
	int unk800b55EC;

	// 800b55f0
	struct TransitionMeta transitionMeta_cupSel[0x6];
	
	// 800b562c
	short cupSel_StarColorIndex[4];
	
	// 800b5634
	short cupSel_StarUnlockFlag[4];
	
	// 800b563c
	int cupSel_Color; // of what?

	// 800b5640
	struct TransitionMeta transitionMeta_battle[0xB];
	
	// 2 byte padding

	// 800b56b0
	struct MenuRow battleType_rows[4];
	
	// 800b56c8
	struct MenuBox battleType_box;
	
	// 800b56f0
	struct MenuRow battleLengthLifeTime_rows[4]; 
	
	// 800b570c
	struct MenuBox battleLengthLifeTime_box;
	
	// 800b5738
	struct MenuRow battleLengthTimeTime_rows[4]; 
	
	// 800b5750
	struct MenuBox battleLengthTimeTime_box;
	
	// 800b577c
	struct MenuRow battleLengthPoints_rows[4]; 
	
	// 800b5794
	struct MenuBox battleLengthPoints_box;
	
	// 800b57c0
	struct MenuRow battleLengthLifeLife_rows[4]; 
	
	// 800b57d8
	struct MenuBox battleLengthLifeLife_box;

	// 800b5804
	struct MenuRow battleStartGame_rows[2];
	
	// 800b5810
	struct MenuBox battleStartGame_box;
	
	// 800b583c
	struct MenuBox* battleMenuBoxArray[5];
	
	// 800b5850
	int battleWeaponsEnabled[22];
	
	// 800b58a8
	int FlagesGameMode1_BattleType[3];
	
	// 800b58b4
	char time_3_6_9[4];
	char time_3_6_INF[4];
	char lives_3_6_9[4];
	char points_5_10_15[4];
	
	// 800b58c4
	char color1[4];
	char color2[4];
	char color3[4];
	
	// ======== End of Battle, Start of High Score ==================
	
	// 800b58d0
	struct TransitionMeta transitionMeta_HighScores[0xC];
	
	// 800b5948
	short colorIndexArray[2];

	// 800b594c
	char fill_MainMenu_LevelRowbattletracks_temporary[0x90];

	// 800b59a0 title object

	// 800b59a4 trackSelect changeTrack frame count
	// 800b59a6 trackSelect changeTrack next track (or curr?)
	// 800b59a8 trackSelect changeTrack next track (or curr?)
	// 800b59aa trackSelect changeTrack direction
	// 800b59ac trackSelect boolOpenLapBox

	// 800b59ae trackSelect transition state
	// 800b59b0 trackSelect post-transition boolStart
	// 800b59b2 trackSelect transitionFrames
	
	// 800b59b4 trackSelect video frame count
	// 800b59b6 trackSelect video boolAllocated
	// 800b59b8 ??
	// 800b59ba ???
	
	// 800b59bc cupSelect transition state
	// 800b59be cupSelect post-transition boolStart
	// 800b59c0 cupSelect transition frames
	
	// 800b59c2 battle transition state
	// 800b59c4 battle post-transition boolStart
	// 800b59c6 battle transition frames
	
	// 800b59c8 highScore transition state
	// 800b59ca highScore transition frames
	// ...

	// 0x800b59dc
	int characterSelect_sizeY;
	
	int unkE0;

	// 0x800b59e4 -- UsaRetail
	// 0x800b6288 -- EurRetail
	// 0x800b9a90 -- JpnRetail
	int movingToTrackMenu;
		
	// 800b59e8
	short characterSelect_MoveDir[4];
	
	// 800b59f0
	short characterSelect_charIDs_desired[4];
	
	// 800b59f8
	short characterSelect_charIDs_curr[4];
	
	// 800b5a00
	short characterSelect_angle[4];
	
	// 800b5a08
	int transitionState;
	
	// 800b5a0c
	short* characterSelect_ptrWindowXY;

	// 800b5a10
	int characterSelectIconLayout;
	
	// 800b5a14
	int unkTimerMM;
	
	// 800b5a18
	struct CharacterSelectMeta* csm_Active;

	// 800b5a1c ???
	int MM_State;

	// 0x800b5a20 -- UsaRetail
	// 0x800b62c4 -- EurRetail
	// 0x800b9acc -- JpnRetail
	// 0 = transitioning in, 1 = in focus/still, 2 = transitioning out
	int isMenuTransitioning;

	// 0x800b5a24
	short timerPerPlayer[4];

	// 800b5a2c
	int isRosterExpanded;

	// 800b5a30
	int characterSelect_sizeX;

	// 800b5a34
	int unkPtr1;
	
	// 800b5a38
	int textPos;

	// 800b5a3c
	struct TransitionMeta* ptrTransitionMeta;
	int countMeta0xD;


	// 800b5a44
	short transitionFrames;
	
} OVR_230;