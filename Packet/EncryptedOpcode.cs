using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MapleShark
{
    public class EncryptedOpcode
    {
        public int EncryptedOp { get; private set; }
        public byte[] RawData { get; private set; }
        public int Index { get; private set; }
        public ushort RealOp { get; private set; }

        public EncryptedOpcode(int pEncryptedOp, byte[] aRawData, int pIndex, ushort pRealOp)
        {
            EncryptedOp = pEncryptedOp;
            RawData = aRawData;
            Index = pIndex;
            RealOp = pRealOp;
        }
    }
}
