package org.example;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

public class CryptoController {

    @FXML
    private TextArea inputField;

    @FXML
    private TextField keyField;

    @FXML
    private TextArea outputField;

    // Metoda wywoływana po kliknięciu "ZASZYFRUJ"
    @FXML
    private void handleEncrypt() {
        String originalText = inputField.getText();
        String key = keyField.getText();

        // Tutaj wstawisz swoją logikę szyfrowania
        String result = "Zaszyfrowano: " + originalText + " (kluczem: " + key + ")";
        outputField.setText(result);
    }

    // Metoda wywoływana po kliknięciu "ODSZYFRUJ"
    @FXML
    private void handleDecrypt() {
        String encryptedText = inputField.getText();
        String key = keyField.getText();

        // Tutaj wstawisz swoją logikę odszyfrowywania
        String result = "Odszyfrowano tekst kluczem: " + key;
        outputField.setText(result);
    }
}