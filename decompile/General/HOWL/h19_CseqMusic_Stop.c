#include <common.h>

void DECOMP_CseqMusic_Stop(int songID)
{
	int i;
	struct Song* song;

	// byte budget,
	// if either of these are false, CseqMusic_Start
	// wouldn't have played to begin with anyway
	#if 0
	if(sdata->boolAudioEnabled == 0) return;
	if(sdata->ptrCseqHeader == 0) return;
	if(sdata->ptrCseqHeader->numSongs <= songID) return;
	#endif
	
	DECOMP_Smart_EnterCriticalSection();
	
	for(i = 0; i < 2; i++)
	{
		song = &sdata->songPool[i];
		
		// if pool is taken
		if (
				((song->flags & 1) != 0) &&
				(song->id == songID)
			)
		{
			DECOMP_SongPool_StopAllCseq(song);
		}
	}
	
	DECOMP_Smart_ExitCriticalSection();
}