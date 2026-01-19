import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import safenet.jcprov.params.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.io.Console;
import java.io.File;

/**
 * StoreDekData Pilot Program
 * 
 * Usage:
 * java StoreDekData [options]
 * 
 * Options:
 * -s, --slot <slotId> HSM Slot ID (REQUIRED)
 * -p, --password <pwd> User Password (REQUIRED, or prompts if interactive)
 * -kl, --kek-label <label> KEK (Master Key) Label (REQUIRED)
 * -dl, --dek-label <label> Label for DEK CKO_DATA object (REQUIRED)
 * -f, --file <file> Path to DEK binary file (REQUIRED)
 * -v, --verify Verification Mode: Read existing DEK, show encrypted data, and
 * verify.
 * -q, --quiet Quiet Mode: Skip "Press Enter" prompts.
 * -h, --help Show this help message.
 */
public class StoreDekData {

    private static Long slotId = null;
    private static String password = null;
    private static String kekLabel = null;
    private static String dekLabel = null;
    private static String dekFilePath = null;
    private static boolean verboseMode = false;
    private static boolean quietMode = false;

    // Helper for console input
    private static Console console = System.console();

    public static void main(String[] args) {
        // Parse arguments
        parseArgs(args);

        // Validation: Check required arguments
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
        if (password == null) {
            missing = true;
            extraMsg.append("Error: Password (-p) is required.\n");
        }

        if (missing) {
            System.err.println(extraMsg.toString());
            printUsage();
            System.exit(1);
        }

        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();

        try {
            System.out.println("=== StoreDekData Pilot Program ===");
            if (verboseMode)
                System.out.println("Mode: VERBOSE (Showing Plaintext/Decrypted values)");
            if (quietMode)
                System.out.println("Mode: QUIET (Skipping prompts)");

            // 1. Initialize & Login
            step("Initialize and Login");
            initialize();
            session = openSession(slotId);
            login(session);

            // 2. Find KEK
            step("Find KEK (Master Key)");
            CK_OBJECT_HANDLE hKek = findKey(session, kekLabel);
            System.out.println("KEK Found. Label: " + kekLabel + ", Handle: " + hKek);

            // --- CREATION FLOW (Always Run) ---

            // 3. Read DEK Plaintext
            step("Read DEK Plaintext from file");
            File dekFile = new File(dekFilePath);
            if (!dekFile.exists()) {
                throw new RuntimeException("DEK file not found: " + dekFilePath);
            }
            byte[] dekPlaintext = Files.readAllBytes(Paths.get(dekFilePath));
            System.out.println("Read " + dekPlaintext.length + " bytes from " + dekFilePath);
            if (verboseMode)
                printHex("Plaintext DEK", dekPlaintext);

            // 4. Encrypt DEK
            step("Encrypt DEK with KEK");
            byte[] encryptedDek = encrypt(session, hKek, dekPlaintext);
            printHex("Encrypted DEK", encryptedDek);

            // 5. Store Ciphertext
            step("Store Encrypted DEK as CKO_DATA");
            storeData(session, dekLabel, encryptedDek);
            System.out.println("CKO_DATA stored successfully with label: " + dekLabel);

            // 6. Read Ciphertext (Always do this to verify storage/retrieval)
            step("Read CKO_DATA from HSM");

            byte[] retrievedCiphertext = readData(session, dekLabel);
            System.out.println("Read CKO_DATA with Label: " + dekLabel);
            printHex("Encrypted DEK (CKO_DATA.VALUE)", retrievedCiphertext); // Always show

            // 7. Decrypt
            step("Decrypt Ciphertext with KEK");
            byte[] decryptedDek = decrypt(session, hKek, retrievedCiphertext);
            if (verboseMode)
                printHex("Decrypted DEK", decryptedDek);

            // 8. Verify
            step("Verification");

            byte[] original = dekPlaintext;
            if (Arrays.equals(original, decryptedDek)) {
                System.out.println("SUCCESS: Decrypted data matches original DEK.");
            } else {
                System.err.println("FAILURE: Decrypted data does NOT match original DEK.");
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup(session);
        }
    }

    // --- Core Functions ---

    private static void parseArgs(String[] args) {
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
            } else if (arg.equals("-v") || arg.equals("--verbose")) {
                verboseMode = true;
            } else if (arg.equals("-q") || arg.equals("--quiet")) {
                quietMode = true;
            } else if (arg.equals("-h") || arg.equals("--help")) {
                printUsage();
                System.exit(0);
            }
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java StoreDekData [options]");
        System.out.println("");
        System.out.println("Options:");
        System.out.println("  -s,  --slot <slotId>       HSM Slot ID (REQUIRED)");
        System.out.println("  -p,  --password <pwd>      User Password (REQUIRED)");
        System.out.println("  -kl, --kek-label <label>   KEK (Master Key) Label (REQUIRED)");
        System.out.println("  -dl, --dek-label <label>   Label for DEK CKO_DATA object (REQUIRED)");
        System.out.println("  -f,  --file <file>         Path to DEK binary file (REQUIRED)");
        System.out.println("  -v,  --verbose             Verbose Mode: Show Plaintext and Decrypted DEK values.");
        System.out.println("  -q,  --quiet               Quiet Mode: Skip 'Press Enter' prompts.");
        System.out.println("  -h,  --help                Show this help message.");
    }

    private static void initialize() throws Exception {
        CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
    }

    private static CK_SESSION_HANDLE openSession(long slotId) throws Exception {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null, session);
        return session;
    }

    private static void login(CK_SESSION_HANDLE session) throws Exception {
        // Password is now enforced to be non-null by check in main()
        CryptokiEx.C_Login(session, CKU.USER, password.getBytes(StandardCharsets.US_ASCII), password.length());
        System.out.println("Login Successful.");
    }

    private static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session, String label) throws Exception {
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

    private static byte[] encrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, byte[] data) throws Exception {
        byte[] iv = new byte[16];
        CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_CBC_PAD, iv);

        CryptokiEx.C_EncryptInit(session, mechanism, hKey);

        LongRef outLen = new LongRef();
        CryptokiEx.C_Encrypt(session, data, data.length, null, outLen);

        byte[] cipherText = new byte[(int) outLen.value];
        CryptokiEx.C_Encrypt(session, data, data.length, cipherText, outLen);

        return Arrays.copyOf(cipherText, (int) outLen.value);
    }

    private static void storeData(CK_SESSION_HANDLE session, String label, byte[] value) throws Exception {
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

    private static byte[] readData(CK_SESSION_HANDLE session, String label) throws Exception {
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

    private static CK_OBJECT_HANDLE findDataHandle(CK_SESSION_HANDLE session, String label) throws Exception {
        CK_ATTRIBUTE[] template = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.DATA),
                new CK_ATTRIBUTE(CKA.LABEL, label.getBytes(StandardCharsets.UTF_8))
        };
        return findObject(session, template);
    }

    private static byte[] decrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hKey, byte[] ciphertext)
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

    private static CK_OBJECT_HANDLE findObject(CK_SESSION_HANDLE session, CK_ATTRIBUTE[] template) throws Exception {
        CryptokiEx.C_FindObjectsInit(session, template, template.length);
        CK_OBJECT_HANDLE[] foundInfo = { new CK_OBJECT_HANDLE() };
        LongRef foundCount = new LongRef();

        CryptokiEx.C_FindObjects(session, foundInfo, 1, foundCount);
        CryptokiEx.C_FindObjectsFinal(session);

        if (foundCount.value == 1) {
            return foundInfo[0];
        }
        return new CK_OBJECT_HANDLE();
    }

    private static void cleanup(CK_SESSION_HANDLE session) {
        try {
            Cryptoki.C_Logout(session);
            Cryptoki.C_CloseSession(session);
            Cryptoki.C_Finalize(null);
        } catch (Exception ignored) {
        }
    }

    private static void step(String description) {
        System.out.println("\n--------------------------------------------------");
        System.out.println("STEP: " + description);
        System.out.println("--------------------------------------------------");
        if (!quietMode && console != null) {
            console.readLine("Press Enter to continue...");
        }
    }

    private static String prompt(String message) {
        if (console != null) {
            return console.readLine(message);
        }
        return "";
    }

    private static void printHex(String label, byte[] data) {
        System.out.print(label + ": ");
        for (byte b : data) {
            System.out.printf("%02X", b);
        }
        System.out.println();
    }
}
