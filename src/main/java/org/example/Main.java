package org.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage stage) throws Exception {
        // Ładuje plik z src/main/resources/view.fxml
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/view.fxml"));
        Scene scene = new Scene(loader.load());
        stage.setScene(scene);
        stage.setTitle("Krypto App 25");
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}