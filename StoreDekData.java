import safenet.jcprov.*;
import safenet.jcprov.constants.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.io.Console;
import java.io.File;

/**
 * StoreDekData Example Program
 * 
 * Usage:
 * java StoreDekData [options]
 * 
 * Options:
 * -s, --slot <slotId> HSM Slot ID (Required)
 * -p, --password <pwd> User Password (Required, interactive prompt if missing)
 * -kl, --kek-label <label> KEK (Master Key) Label (Required)
 * -dl, --dek-label <label> DEK CKO_DATA Object Label (Required)
 * -f, --file <file> DEK Binary File Path (Required)
 * -h, --help Show this help message.
 */
public class StoreDekData {

    private Long slotId = null;
    private String password = null;
    private String kekLabel = null;
    private String dekLabel = null;
    private String dekFilePath = null;

    // Console input helper
    private Console console = System.console();

    public static void main(String[] args) {
        StoreDekData program = new StoreDekData();
        program.run(args);
    }

    public void run(String[] args) {
        // Parse arguments
        parseArgs(args);

        // Validation
        validateArgs();

        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();

        try {
            System.out.println("=== StoreDekData Example Program ===");

            // 1. Initialization and Login
            step("Initialization and Login");
            initialize();
            session = openSession(slotId);
            login(session);

            // 2. Find KEK
            step("Find KEK (Master Key)");
            CK_OBJECT_HANDLE hKek = findKey(session, kekLabel);
            System.out.println("KEK Found. Label: " + kekLabel + ", Handle: " + hKek);

            // 3. Read DEK Plaintext
            step("Read DEK Plaintext from File");
            File dekFile = new File(dekFilePath);
            if (!dekFile.exists()) {
                throw new RuntimeException("DEK File not found: " + dekFilePath);
            }
            byte[] dekPlaintext = Files.readAllBytes(Paths.get(dekFilePath));
            System.out.println("Read " + dekPlaintext.length + " bytes from " + dekFilePath);
            printHex("DEK Plaintext", dekPlaintext);

            // 4. Encrypt DEK
            step("Encrypt DEK with KEK");
            byte[] encryptedDek = encrypt(session, hKek, dekPlaintext);
            System.out.println("DEK Encryption Complete (" + encryptedDek.length + " bytes)");
            printHex("Encrypted DEK", encryptedDek);

            // 5. Store Ciphertext
            step("Store Encrypted DEK as CKO_DATA");
            storeData(session, dekLabel, encryptedDek);
            System.out.println("CKO_DATA Stored Successfully. Label: " + dekLabel);

            // 6. Read Ciphertext (Always performed for verification)
            step("Read CKO_DATA from HSM");

            byte[] retrievedCiphertext = readData(session, dekLabel);
            System.out.println("CKO_DATA Read Successfully. Label: " + dekLabel);

            // 7. Decrypt
            step("Decrypt Ciphertext with KEK");
            byte[] decryptedDek = decrypt(session, hKek, retrievedCiphertext);
            printHex("Decrypted DEK", decryptedDek);

            // 8. Verify
            step("Verification");

            byte[] original = dekPlaintext;
            if (Arrays.equals(original, decryptedDek)) {
                System.out.println("Success: Decrypted data matches original DEK.");
            } else {
                System.err.println("Failure: Decrypted data does NOT match original DEK.");
                // Ensure we exit with error code on failure
                System.exit(1);
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } finally {
            cleanup(session);
        }
    }

    private void validateArgs() {
        boolean missing = false;
        StringBuilder extraMsg = new StringBuilder();

        if (slotId == null) {
            missing = true;
            extraMsg.append("Error: Slot ID (-s) is required.\n");
        }
        if (kekLabel == null) {
            missing = true;
            extraMsg.append("Error: KEK Label (-kl) is required.\n");
        }
        if (dekLabel == null) {
            missing = true;
            extraMsg.append("Error: DEK Label (-dl) is required.\n");
        }
        if (dekFilePath == null) {
            missing = true;
            extraMsg.append("Error: DEK File Path (-f) is required.\n");
        }
        if (password == null) { // Password required
            if (console != null) {
                char[] pwdChars = console.readPassword("Enter HSM Password: ");
                if (pwdChars != null) {
                    password = new String(pwdChars);
                }
            }
        }

        if (password == null) {
            missing = true;
            extraMsg.append("Error: Password (-p) is required (or interactive input unavailable).\n");
        }

        if (missing) {
            System.err.println(extraMsg.toString());
            printUsage();
            System.exit(1);
        }
    }

    private void parseArgs(String[] args) {
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-s") || arg.equals("--slot")) {
                if (i + 1 < args.length)
                    slotId = Long.parseLong(args[++i]);
            } else if (arg.equals("-p") || arg.equals("--password")) {
                if (i + 1 < args.length)
                    password = args[++i];
            } else if (arg.equals("-kl") || arg.equals("--kek-label")) {
                if (i + 1 < args.length)
                    kekLabel = args[++i];
            } else if (arg.equals("-dl") || arg.equals("--dek-label")) {
                if (i + 1 < args.length)
                    dekLabel = args[++i];
            } else if (arg.equals("-f") || arg.equals("--file")) {
                if (i + 1 < args.length)
                    dekFilePath = args[++i];
            } else if (arg.equals("-h") || arg.equals("--help")) {
                printUsage();
                System.exit(0);
            }
        }
    }

    private void printUsage() {
        System.out.println("Usage: java StoreDekData [options]");
        System.out.println("");
        System.out.println("Options:");
        System.out.println("  -s,  --slot <slotId>       HSM Slot ID (Required)");
        System.out.println("  -p,  --password <pwd>      User Password (Required, prompts if missing)");
        System.out.println("  -kl, --kek-label <label>   KEK (Master Key) Label (Required)");
        System.out.println("  -dl, --dek-label <label>   DEK CKO_DATA Object Label (Required)");
        System.out.println("  -f,  --file <file>         DEK Binary File Path (Required)");
        System.out.println("  -h,  --help                Show this help message");
    }

    private void initialize() throws Exception {
        CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
    }

    private CK_SESSION_HANDLE openSession(long slotId) throws Exception {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null, session);
        return session;
    }

    private void login(CK_SESSION_HANDLE session) throws Exception {
        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(StandardCharsets.US_ASCII), password.length());
        System.out.println("Login successful.");
    }

    private CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session, String label) throws Exception {
        CK_ATTRIBUTE[] template = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
                new CK_ATTRIBUTE(CKA.LABEL, label.getBytes(StandardCharsets.UTF_8))
        };

        CK_OBJECT_HANDLE hKey = findObject(session, template);
        if (!hKey.isValidHandle()) {
            throw new RuntimeException("Key not found: " + label);
        }
        return hKey;
    }

    private byte[] encrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, byte[] data) throws Exception {
        byte[] iv = new byte[16]; // Zero IV for pilot
        CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_CBC_PAD, iv);

        CryptokiEx.C_EncryptInit(session, mechanism, hKey);

        LongRef outLen = new LongRef();
        CryptokiEx.C_Encrypt(session, data, data.length, null, outLen);

        byte[] cipherText = new byte[(int) outLen.value];
        CryptokiEx.C_Encrypt(session, data, data.length, cipherText, outLen);

        return Arrays.copyOf(cipherText, (int) outLen.value);
    }

    private void storeData(CK_SESSION_HANDLE session, String label, byte[] value) throws Exception {
        // First delete if exists
        try {
            CK_OBJECT_HANDLE existing = findDataHandle(session, label);
            if (existing.isValidHandle()) {
                CryptokiEx.C_DestroyObject(session, existing);
                System.out.println("Overwriting existing data object: " + label);
            }
        } catch (Exception ignored) {
        }

        CK_ATTRIBUTE[] template = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.DATA),
                new CK_ATTRIBUTE(CKA.LABEL, label.getBytes(StandardCharsets.UTF_8)),
                new CK_ATTRIBUTE(CKA.VALUE, value),
                new CK_ATTRIBUTE(CKA.TOKEN, new CK_BBOOL(true)), // Persistent
                new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(true)) // Private
        };

        CK_OBJECT_HANDLE hData = new CK_OBJECT_HANDLE();
        CryptokiEx.C_CreateObject(session, template, template.length, hData);
    }

    private byte[] readData(CK_SESSION_HANDLE session, String label) throws Exception {
        CK_OBJECT_HANDLE hData = findDataHandle(session, label);
        if (!hData.isValidHandle()) {
            throw new RuntimeException("Data object not found: " + label);
        }

        // Use CTUtilEx to safely get attribute value length and data
        LongRef lRef = new LongRef();

        // 1. Get Size
        CTUtilEx.CTU_GetAttributeValue(session, hData, CKA.VALUE, null, 0, lRef);

        // 2. Allocate and Get Data
        byte[] data = new byte[(int) lRef.value];
        CTUtilEx.CTU_GetAttributeValue(session, hData, CKA.VALUE, data, data.length, lRef);

        return data;
    }

    private CK_OBJECT_HANDLE findDataHandle(CK_SESSION_HANDLE session, String label) throws Exception {
        CK_ATTRIBUTE[] template = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.DATA),
                new CK_ATTRIBUTE(CKA.LABEL, label.getBytes(StandardCharsets.UTF_8))
        };
        return findObject(session, template);
    }

    private byte[] decrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, byte[] ciphertext)
            throws Exception {
        byte[] iv = new byte[16];
        CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_CBC_PAD, iv);

        CryptokiEx.C_DecryptInit(session, mechanism, hKey);

        LongRef outLen = new LongRef();
        CryptokiEx.C_Decrypt(session, ciphertext, ciphertext.length, null, outLen);

        byte[] plaintext = new byte[(int) outLen.value];
        CryptokiEx.C_Decrypt(session, ciphertext, ciphertext.length, plaintext, outLen);

        return Arrays.copyOf(plaintext, (int) outLen.value);
    }

    // --- Utilities ---

    private CK_OBJECT_HANDLE findObject(CK_SESSION_HANDLE session, CK_ATTRIBUTE[] template) throws Exception {
        CryptokiEx.C_FindObjectsInit(session, template, template.length);
        CK_OBJECT_HANDLE[] foundInfo = new CK_OBJECT_HANDLE[10];
        for (int i = 0; i < foundInfo.length; i++) {
            foundInfo[i] = new CK_OBJECT_HANDLE();
        }
        LongRef foundCount = new LongRef();

        CryptokiEx.C_FindObjects(session, foundInfo, foundInfo.length, foundCount);
        CryptokiEx.C_FindObjectsFinal(session);

        if (foundCount.value == 0) {
            return new CK_OBJECT_HANDLE();
        }

        if (foundCount.value > 1) {
            System.err.println(
                    "Warning: " + foundCount.value + " objects found with same criteria. Using the first one.");
        }

        return foundInfo[0];
    }

    private void cleanup(CK_SESSION_HANDLE session) {
        try {
            if (session != null && session.isValidHandle()) {
                Cryptoki.C_Logout(session);
                Cryptoki.C_CloseSession(session);
            }
            Cryptoki.C_Finalize(null);
        } catch (Exception ignored) {
        }
    }

    private void step(String description) {
        System.out.println("\n--------------------------------------------------");
        System.out.println("STEP: " + description);
        System.out.println("--------------------------------------------------");
    }

    private void printHex(String label, byte[] data) {
        System.out.println(label + ":");
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        System.out.println(sb.toString());
    }
}
