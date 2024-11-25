using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace BFASenado.Models
{
    [Table("Transaccion")]
    public partial class Transaccion
    {
        [Key]
        public long Id { get; set; }
        [StringLength(100)]
        [Unicode(false)]
        public string Hash { get; set; } = null!;
        [Column(TypeName = "text")]
        public string Base64 { get; set; } = null!;
    }
}
