#include <common.h>

void DECOMP_SongPool_StopCseq(struct SongSeq* seq)
{
	struct ChannelStats* curr;
	u_int* flagPtr;
	
	for(
			curr = sdata->channelTaken.first;
			curr != 0;
			curr = curr->next
		)
	{
		// type != MUSIC
		if(curr->type != 2) continue;
		
		// This line doesn't work, ND Box -> Loading screen
		// does not stpo "all" sounds, unless commented out.
		// Without this line, the game can't stop "individual"
		// music sequences, but the game never does that anyway
		#if 0
		if(curr->soundID != (int)seq->soundID) continue;
		#endif
		
		// enable OFF(1) flag, disable ON(2) flag
		flagPtr = &sdata->ChannelUpdateFlags[curr->channelID];
		*flagPtr |= 1;
		*flagPtr &= ~(2);
		
		*(u_char*)&curr->flags &= 0xfe;
		
		// recycle: remove from taken, put on free
		LIST_RemoveMember(&sdata->channelTaken.first, curr);
		LIST_AddBack(&sdata->channelFree.first, curr);
	}
	
	// not playing
	*(u_char*)&seq->flags &= 0xfe;
}