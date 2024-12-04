using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BFASenado.Models
{
    [Table("TransaccionBFA")]
    [Index("HashHexa", "HashSHA256", Name = "UK_TransaccionBFA", IsUnique = true)]
    public partial class TransaccionBFA
    {
        [Key]
        public long Id { get; set; }

        [Column("IdTabla")]
        public long IdTabla { get; set; }

        [Column("NombreTabla")]
        [StringLength(100)]
        public string NombreTabla { get; set; } = null!;

        [Column("TipoDocumento")]
        [StringLength(100)]
        public string TipoDocumento { get; set; } = null!;

        [Column("HashSHA256")]
        [StringLength(100)]
        public string HashSHA256 { get; set; } = null!;

        [Column("HashHexa")]
        [StringLength(100)]
        public string HashHexa { get; set; } = null!;

        [Column("Base64", TypeName = "text")]
        public string Base64 { get; set; } = null!;

        [Column("Detalles")]
        [StringLength(100)]
        public string? Detalles { get; set; }

        [Column("FechaAltaTabla", TypeName = "datetime")]
        public DateTime FechaAltaTabla { get; set; }

        [Column("FechaAltaBFA", TypeName = "datetime")]
        public DateTime? FechaAltaBFA { get; set; }

        [Column("SnAltaBFA")]
        public bool? SnAltaBFA { get; set; }
    }
}
