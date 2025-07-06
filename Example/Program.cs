using System.Text;
using EonaCat.Crypto;
using EonaCat.Crypto.Helpers;

class Program
{
    static void Main()
    {
        // Generate a random 128-byte (1024-bit) key
        byte[] key = new byte[128];
        RandomNumberGeneratorCustom.ComputeHash(key);

        var crypto = new EonaCatCrypto("WERKT DIT GEWOON?");
        //var crypto = new EonaCatCrypto(key);

        string longLoremIpsum = @"
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua! 
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. 
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur? 
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. 
Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. 
Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem.

Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? 
Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?

At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga. 
Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus.

Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. 
Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat.

Special characters test: !@#$%^&*()_+-=[]{}|;':\"",./<>?`~ 
Unicode symbols: © ® ™ € £ ¥ ∞ ≈ ≠ ≤ ≥ µ ∑ π √ ∫ ∂ ∆ ∇ Ω α β γ δ ε ζ η θ 𝜃 λ µ ν ξ π ρ σ τ φ χ ψ ω
Accents and diacritics: à á â ã ä å æ ç è é ê ë ì í î ï ñ ò ó ô õ ö ø ù ú û ü ý ÿ
Quotes and dashes: “ ” ‘ ’ — – …

End of test string.
";

        Console.WriteLine("Original text length: " + longLoremIpsum.Length);

        byte[] plaintext = Encoding.UTF8.GetBytes(longLoremIpsum);

        // Encrypt text
        byte[] encrypted = crypto.Encrypt(plaintext);
        Console.WriteLine("Encrypted (base64): " + Convert.ToBase64String(encrypted));

        // Decrypt text
        var crypto2 = new EonaCatCrypto("WERKT DIT GEWOON?");
        byte[] decrypted = crypto2.Decrypt(encrypted);

        string decryptedText = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine("Decrypted text length: " + decryptedText.Length);
        if (longLoremIpsum == decryptedText)
        {
            Console.WriteLine("SUCCESS: Decrypted text matches original!");
        }
        else
        {
            Console.WriteLine("FAILURE: Decrypted text does NOT match original!");
        }

        // Example file paths
        string inputFilePath = "Malenia.mp3";
        string encryptedFilePath = "Malenia.mp3.dat";
        string decryptedFilePath = "Malenia_decrypted.mp3";

        if (!File.Exists(inputFilePath))
        {
            inputFilePath = "EonaCat.Crypto.SampleFile.txt";
            encryptedFilePath = "EonaCat.Crypto.SampleFile.dat";
            decryptedFilePath = "EonaCat.Crypto.SampleFile_decrypted.txt";
            // Create a sample file if it doesn't exist
            File.WriteAllText(inputFilePath, longLoremIpsum);
            Console.WriteLine($"Sample file created: {inputFilePath}");
        }

        // Encrypt file
        EonaCatCrypto.EncryptFile(inputFilePath, encryptedFilePath, crypto);

        // Decrypt file
        EonaCatCrypto.DecryptFile(encryptedFilePath, decryptedFilePath, crypto);

        Console.WriteLine("File encryption and decryption completed.");
    }
}
