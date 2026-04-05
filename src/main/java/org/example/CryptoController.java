package org.example;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import java.io.File;
import java.nio.file.Files;
import java.util.Base64;

public class CryptoController {
    private final AES aes = new AES();
    private File selectedFile;

    @FXML private TextArea inputField;
    @FXML private TextField keyField;
    @FXML private TextArea outputField;

    @FXML
    private void handleGenKey() {
        byte[] key = aes.generowanieklucza();
        keyField.setText(Base64.getEncoder().encodeToString(key));
    }

    @FXML
    private void handleOpenFile() {
        FileChooser fileChooser = new FileChooser();
        selectedFile = fileChooser.showOpenDialog(inputField.getScene().getWindow());
        if (selectedFile != null) {
            inputField.setText("WYBRANO PLIK: " + selectedFile.getName() +
                    "\nŚcieżka: " + selectedFile.getAbsolutePath());
            outputField.setText("Plik gotowy. Kliknij Szyfruj lub Odszyfruj.");
        }
    }

    @FXML
    private void handleEncrypt() {
        try {
            String keyStr = keyField.getText().trim();
            if (keyStr.isEmpty()) return;
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);

            if (selectedFile != null) {
                // 1. Szyfrujemy dane w pamięci
                byte[] fileContent = Files.readAllBytes(selectedFile.toPath());
                byte[] encryptedData = aes.encrypt(fileContent, keyBytes);

                // 2. Otwieramy okno "Zapisz jako"
                FileChooser saveChooser = new FileChooser();
                saveChooser.setTitle("Zapisz zaszyfrowany plik");
                saveChooser.setInitialFileName(selectedFile.getName() + ".enc");
                File outFile = saveChooser.showSaveDialog(inputField.getScene().getWindow());

                if (outFile != null) {
                    Files.write(outFile.toPath(), encryptedData);
                    outputField.setText("Zapisano zaszyfrowany plik: " + outFile.getName());
                }
                selectedFile = null;
                inputField.clear();
            } else {
                // Szyfrowanie tekstu (zostaje bez zmian)
                String text = inputField.getText();
                if (text.isEmpty()) return;
                byte[] encrypted = aes.encrypt(text.getBytes("UTF-8"), keyBytes);
                outputField.setText(Base64.getEncoder().encodeToString(encrypted));
                inputField.clear();
            }
        } catch (Exception e) {
            outputField.setText("Błąd: " + e.getMessage());
        }
    }

    @FXML
    private void handleDecrypt() {
        try {
            String keyStr = keyField.getText().trim();
            if (keyStr.isEmpty()) return;
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);

            if (selectedFile != null) {
                // 1. Deszyfrujemy dane
                byte[] fileContent = Files.readAllBytes(selectedFile.toPath());
                byte[] decryptedData = aes.decrypt(fileContent, keyBytes);

                // 2. Otwieramy okno "Zapisz jako"
                FileChooser saveChooser = new FileChooser();
                saveChooser.setTitle("Zapisz odszyfrowany plik");

                // Sugerujemy nazwę bez ".enc" lub ".encrypted"
                String suggestedName = selectedFile.getName().replace(".enc", "").replace(".encrypted", "");
                saveChooser.setInitialFileName("decoded_" + suggestedName);

                File outFile = saveChooser.showSaveDialog(inputField.getScene().getWindow());

                if (outFile != null) {
                    Files.write(outFile.toPath(), decryptedData);
                    outputField.setText("Plik odszyfrowany i zapisany jako: " + outFile.getName());
                }
                selectedFile = null;
                inputField.clear();
            } else {
                // Deszyfrowanie tekstu (zostaje bez zmian)
                String cryptedText = outputField.getText().replaceAll("\\s", "");
                if (cryptedText.isEmpty()) return;
                byte[] decrypted = aes.decrypt(Base64.getDecoder().decode(cryptedText), keyBytes);
                inputField.setText(new String(decrypted, "UTF-8"));
                outputField.setText("Tekst odszyfrowany.");
            }
        } catch (Exception e) {
            outputField.setText("Błąd: " + e.getMessage());
        }
    }
    // TA METODA NAPRAWIA TWÓJ BŁĄD STARTU (FXMLLoader jej szukał)
    @FXML
    private void handleSaveFile() {
        outputField.setText("Info: Pliki są zapisywane automatycznie po operacji.");
    }
}