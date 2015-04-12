unsigned int	BytesSHA1(uchar *Data, uint Length);
void	GenSessionKey(uchar *Buffer, uint Size);
void	SpecialSHA(uchar *SessionKey, uint SkSz, uchar *SHAResult, uint ResSz);
uchar		*FinalizeLoginDatas(uchar *Buffer, uint *Size, uchar *Suite, int SuiteSz);
__int64 BytesSHA1I64(uchar *Data, uint Length);
__int64 BytesRandomI64();
void	BuildUnFinalizedDatas(uchar *Datas, uint Size, uchar *Result);
