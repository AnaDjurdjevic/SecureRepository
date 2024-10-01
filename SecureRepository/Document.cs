using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureRepository
{
    internal class Document
    {
        public string OriginalDocumentName { get; set; }
        public string [] PathToSegment { get;set; }

        public byte[][] DigitalSignature { get; set; }

        public override bool Equals(object? obj)
        {
            if (obj == null)
                return false;
            if (obj is Document doc)
                return doc.OriginalDocumentName.Equals(this.OriginalDocumentName);
            return false;

        }
    }
}
