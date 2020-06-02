using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;

namespace AspNetCoreIdentity.Models
{
    public class CustomPasswordValidator : IPasswordValidator<User>
    {
        public int RequiredLength { get; set; } // минимальная длина

        public CustomPasswordValidator(int length)
        {
            RequiredLength = length;
        }

        public Task<IdentityResult> ValidateAsync(UserManager<User> manager, User user, string password)
        {
            List<IdentityError> errors = new List<IdentityError>();

            if (String.IsNullOrEmpty(password) || password.Length < RequiredLength)
            {
                errors.Add(new IdentityError
                {
                    Description = $"Минимальная длина пароля равна {RequiredLength}"
                });
            }
            string pattern = "(?=^.{5,}$)((?=.*\\d)|(?=.*\\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"; //Строчные и прописные латинские буквы, цифры, спецсимволы. Минимум 8 символов

            if (!Regex.IsMatch(password, pattern))
            {
                errors.Add(new IdentityError
                {
                    Description = "Использованы запрещенные символы"
                });
            }
            return Task.FromResult(errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray()));
        }
    }
}
