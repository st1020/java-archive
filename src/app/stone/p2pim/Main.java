package app.stone.p2pim;
// 基于区块链技术的P2P聊天软件
/*
说明：
这是一个基于区块链技术的端到端聊天软件，功能比较简陋，但基本实现了功能。
使用了区块链和 RSA 数字签名保证了聊天记录绝对不可篡改。
类似 HTTP 协议，在每个 Socket 上仅进行一个请求。
类似主流 IM，支持多个聊天会话（即可以同时和多个人聊天），所有会话共用一个用于接收消息的端口。
启动后会默认添加一个和自己的聊天会话，本地测试时可以开两个实例在本地进行聊天，第二个实例在启动时会提示端口被占用，需要指定新的接收消息端口。
此软件通过用户名而非 IP 地址识别用户，使用时需要双方手动添加聊天会话，指定用户名，公钥，IP 和端口，但之后即使对方的 IP 变化，只要用户名和公钥不变就可以自动切换 IP。
此软件每次启动时默认用户名为 Alice，接收端口为 1234，公钥和私钥随机生成，可以通过设置进行更改，设置保存后命令行出现 Socket closed 是正常的。
测试时请保证两个实例设置的用户名不同，聊天时输入回车发送消息。
此软件仅具有非常基础的错误处理，不能保证在非正确输入时仍能正常工作。
在 macOS 12 系统 OpenJDK 17 with JavaFX 上开发测试。
PS. Java 不自带 JSON 解析，不然我肯定用 JSON 而不是手动构建字符串了。

Author: st1020
License: Apache License 2.0
*/

import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.*;
import javafx.scene.text.Font;
import javafx.stage.Stage;
import javafx.util.Callback;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.util.*;

public class Main extends Application {
    ChatServer chatServer = null;
    ListView<ChatSession> listView = null;
    ChatSession currentChatSession = null;

    VBox vBoxFriends = new VBox();
    VBox vBoxChats = new VBox();
    TextArea textAreaInput = new TextArea();

    class UpdateMessage implements Callback<ChatSession, Object> {
        @Override
        public Object call(ChatSession param) {
            Block lastMessage = param.blockChain.get(param.blockChain.size() - 1);
            if (Objects.equals(lastMessage.name, param.name)) {
                Platform.runLater(() -> addMessage(lastMessage));
            }
            return null;
        }
    }

    public static void main(String[] args) {
        launch(args);
    }

    void initListView() {
        class ColorCell extends ListCell<ChatSession> {
            @Override
            protected void updateItem(ChatSession item, boolean empty) {
                super.updateItem(item, empty);
                if (item != null) {
                    Label labelName = new Label(item.name);
                    labelName.setFont(Font.font(24));
                    Label labelSign = new Label(item.rsaSign.getPublicKeyString().substring(40, 50) + "  ");
                    setGraphic(new VBox(labelName, labelSign));
                } else {
                    setGraphic(null);
                }
            }
        }
        listView = new ListView<>(chatServer.observableList);
        listView.setCellFactory((ListView<ChatSession> l) -> new ColorCell());
        listView.getSelectionModel().selectedIndexProperty().addListener(
                (observable, oldValue, newValue) -> {
                    currentChatSession = chatServer.observableList.get((Integer) newValue);
                    refreshMessage();
                }
        );
    }

    void initVBoxFriends() {
        Button buttonCreateChat = new Button("创建聊天");
        buttonCreateChat.setOnAction(event -> {
            TextField textFieldName = new TextField();
            TextField textFieldPublicKey = new TextField();
            TextField textFieldHost = new TextField();
            TextField textFieldPort = new TextField();

            GridPane gridPane = new GridPane();
            gridPane.add(new Label("Name: "), 0, 0);
            gridPane.add(textFieldName, 1, 0);
            gridPane.add(new Label("PublicKey: "), 0, 1);
            gridPane.add(textFieldPublicKey, 1, 1);
            gridPane.add(new Label("Host: "), 0, 2);
            gridPane.add(textFieldHost, 1, 2);
            gridPane.add(new Label("Port: "), 0, 3);
            gridPane.add(textFieldPort, 1, 3);
            gridPane.setVgap(5);
            gridPane.setHgap(5);

            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("创建聊天");
            alert.setHeaderText("请输入设置项：");
            alert.getDialogPane().setContent(gridPane);
            Optional<ButtonType> result = alert.showAndWait();
            if (result.isPresent() && result.get() == ButtonType.OK) {
                try {
                    chatServer.observableList.add(
                            new ChatSession(
                                    textFieldHost.getText(),
                                    Integer.parseInt(textFieldPort.getText()),
                                    textFieldName.getText(),
                                    textFieldPublicKey.getText()
                            )
                    );
                } catch (GeneralSecurityException e) {
                    e.printStackTrace();
                }
            }
        });

        Button buttonImportChat = new Button("导入/导出");
        buttonImportChat.setOnAction(event -> {
            if (currentChatSession != null) {
                TextArea textArea = new TextArea(currentChatSession.blockChain.toString());
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("导入/导出聊天记录");
                alert.setHeaderText("请输入符合格式的聊天记录区块链文本：");
                alert.getDialogPane().setContent(new Pane(textArea));
                Optional<ButtonType> result = alert.showAndWait();
                if (result.isPresent() && result.get() == ButtonType.OK) {
                    try {
                        currentChatSession.blockChain = new BlockChain(textArea.getText());
                        refreshMessage();
                    } catch (BlockParseException e) {
                        e.printStackTrace();
                    }
                }
            }
        });

        Button buttonSetting = new Button("设置");
        buttonSetting.setOnAction(event -> {
            StringWriter stringWriter = new StringWriter();
            try {
                chatServer.properties.store(stringWriter, "IM Setting");
            } catch (IOException e) {
                e.printStackTrace();
            }
            TextArea textArea = new TextArea(stringWriter.toString());
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("设置");
            alert.setHeaderText("请输入设置项：");
            alert.getDialogPane().setContent(new Pane(textArea));
            Optional<ButtonType> result = alert.showAndWait();
            if (result.isPresent() && result.get() == ButtonType.OK) {
                try {
                    Properties properties = new Properties();
                    properties.load(new StringReader(textArea.getText()));
                    chatServer.setProperties(properties);
                } catch (IOException | GeneralSecurityException e) {
                    e.printStackTrace();
                }
            }
        });

        HBox hBoxAddFriendTools = new HBox();
        hBoxAddFriendTools.getChildren().addAll(buttonCreateChat, buttonImportChat, buttonSetting);

        vBoxFriends.getChildren().addAll(hBoxAddFriendTools, listView);
    }

    void addMessage(Block block) {
        DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.CHINA);
        Label labelNameTime = new Label(block.name + "  " + dateFormat.format(new Date(block.time)));
        Label labelText = new Label(block.text);
        labelText.setFont(new Font(25));
        VBox vBox = new VBox();
        vBox.getChildren().addAll(labelNameTime, labelText);
        if (Objects.equals(block.name, chatServer.properties.getProperty("name"))) {
            vBox.setAlignment(Pos.BASELINE_RIGHT);
        } else {
            vBox.setAlignment(Pos.BASELINE_LEFT);
        }
        vBoxChats.getChildren().add(vBox);
    }

    void refreshMessage() {
        vBoxChats.getChildren().clear();
        if (currentChatSession != null) {
            for (Block block : currentChatSession.blockChain) {
                addMessage(block);
            }
        }
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        try {
            chatServer = new ChatServer(1234, "Alice");
        } catch (BindException e) {
            TextInputDialog dialog = new TextInputDialog("1234");
            dialog.setTitle("错误");
            dialog.setHeaderText("端口被占用");
            dialog.setContentText("请输入新的端口：");
            Optional<String> result = dialog.showAndWait();
            if (result.isPresent()) {
                chatServer = new ChatServer(Integer.parseInt(result.get()), "Alice");
            } else {
                System.exit(0);
            }
        }
        chatServer.register(new UpdateMessage());
        initListView();
        initVBoxFriends();

        ScrollPane scrollPane = new ScrollPane(vBoxChats);
        scrollPane.setVbarPolicy(ScrollPane.ScrollBarPolicy.ALWAYS);
        scrollPane.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        SplitPane splitPaneChatBox = new SplitPane();
        splitPaneChatBox.setOrientation(Orientation.VERTICAL);
        splitPaneChatBox.getItems().addAll(scrollPane, textAreaInput);
        splitPaneChatBox.setDividerPositions(0.7);
        splitPaneChatBox.widthProperty().addListener(
                (observable, oldValue, newValue) -> vBoxChats.setPrefWidth(newValue.doubleValue() - 25)
        );
        //vBoxChats.prefWidthProperty().bind(splitPaneChatBox.widthProperty());
        //这里不能直接绑定，因为ScrollPane的竖向滚动条也有宽度

        SplitPane splitPaneMain = new SplitPane();
        splitPaneMain.getItems().addAll(vBoxFriends, splitPaneChatBox);
        splitPaneMain.setDividerPositions(0.3);

        textAreaInput.setOnKeyPressed(event -> {
            if (event.getCode() == KeyCode.ENTER) {
                if (currentChatSession != null) {
                    try {
                        String text = textAreaInput.getText().replaceAll("\\s+$", "");
                        currentChatSession.send(chatServer.rsaSign, chatServer.properties.getProperty("name"), text);
                        textAreaInput.clear();
                        Block lastMessage = currentChatSession.blockChain.get(currentChatSession.blockChain.size() - 1);
                        addMessage(lastMessage);
                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                    }
                }
            }
        });

        Scene scene = new Scene(splitPaneMain, 675, 450);
        primaryStage.setScene(scene);
        primaryStage.setTitle("基于区块链的P2P聊天工具");
        primaryStage.setResizable(false);
        primaryStage.show();
        // listView.setPrefSize(vBoxFriends.getWidth(), vBoxFriends.getHeight());
    }
}

class RSASign {
    PrivateKey privateKey;
    PublicKey publicKey;

    RSASign() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    RSASign(String publicKeyString) throws GeneralSecurityException {
        publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(
                        Base64.getDecoder().decode(publicKeyString)));
    }

    RSASign(String privateKeyString, String publicKeyString) throws GeneralSecurityException {
        privateKey = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(
                        Base64.getDecoder().decode(privateKeyString)));
        publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(
                        Base64.getDecoder().decode(publicKeyString)));
    }

    public String getPrivateKeyString() {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public String getPublicKeyString() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public String getSign(String text) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(text.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public boolean getVerify(String text, String sign) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(text.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getDecoder().decode(sign));
    }
}

class ChatServer {
    Properties properties;
    RSASign rsaSign;

    final ArrayList<ChatSession> chatSessions = new ArrayList<>();
    final ObservableList<ChatSession> observableList = FXCollections.observableList(chatSessions);

    Thread threadServer;
    ServerSocket serverSocket;

    Callback<ChatSession, Object> callback;

    ChatServer(int port, String name) throws GeneralSecurityException, IOException {
        rsaSign = new RSASign();
        properties = new Properties();
        properties.setProperty("receivePort", String.valueOf(port));
        properties.setProperty("name", name);
        properties.setProperty("privateKey", rsaSign.getPrivateKeyString());
        properties.setProperty("publicKey", rsaSign.getPublicKeyString());
        observableList.add(new ChatSession(
                "127.0.0.1",
                Integer.parseInt(properties.getProperty("receivePort")),
                properties.getProperty("name"),
                properties.getProperty("publicKey")
        ));
        startReceiveServer();
    }

    void startReceiveServer() throws IOException {
        serverSocket = new ServerSocket(Integer.parseInt(properties.getProperty("receivePort")));
        threadServer = new Thread(() -> {
            try {
                while (true) {
                    Socket socket = serverSocket.accept();
                    InetAddress inetAddress = socket.getInetAddress();
                    new Thread(() -> {
                        try {
                            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                            String string = dataInputStream.readUTF();
                            try {
                                Block block = new Block(string);
                                if (Objects.equals(block.name, properties.getProperty("name"))) {
                                    return;
                                }
                                synchronized (chatSessions) {
                                    for (ChatSession chatSession : chatSessions) {
                                        if (Objects.equals(block.name, chatSession.name)) {
                                            if (!Objects.equals(inetAddress.getHostAddress(), chatSession.host)) {
                                                chatSession.host = inetAddress.getHostAddress();
                                            }
                                            if (chatSession.add(block)) {
                                                if (callback != null) {
                                                    callback.call(chatSession);
                                                }
                                            } else {
                                                Platform.runLater(() -> {
                                                    Alert alert = new Alert(Alert.AlertType.ERROR);
                                                    alert.setTitle("错误");
                                                    alert.setHeaderText("签名验证错误！");
                                                    alert.setContentText(block.toString());
                                                    alert.showAndWait();
                                                });
                                            }
                                        }
                                    }
                                }
                            } catch (BlockParseException e) {
                                Platform.runLater(() -> {
                                    Alert alert = new Alert(Alert.AlertType.ERROR);
                                    alert.setTitle("错误");
                                    alert.setHeaderText("数据验证错误！");
                                    alert.setContentText(string);
                                    alert.showAndWait();
                                });
                            }
                        } catch (IOException | GeneralSecurityException e) {
                            e.printStackTrace();
                        } finally {
                            try {
                                socket.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }).start();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        threadServer.setDaemon(true);
        threadServer.start();
    }

    void closeReceiveServer() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
        }
    }

    void register(Callback<ChatSession, Object> callback) {
        this.callback = callback;
    }

    void setProperties(Properties newProperties) throws IOException, GeneralSecurityException {
        properties = newProperties;
        closeReceiveServer();
        rsaSign = new RSASign(properties.getProperty("privateKey"), properties.getProperty("publicKey"));
        observableList.set(0, new ChatSession(
                "127.0.0.1",
                Integer.parseInt(properties.getProperty("receivePort")),
                properties.getProperty("name"),
                properties.getProperty("publicKey"),
                observableList.get(0).blockChain
        ));
        startReceiveServer();
    }
}

class ChatSession {
    String host;
    int port;
    String name;
    RSASign rsaSign;
    BlockChain blockChain;

    ChatSession(String host, int port, String name, String publicKeyString) throws GeneralSecurityException {
        this.host = host;
        this.port = port;
        this.name = name;
        this.rsaSign = new RSASign(publicKeyString);
        this.blockChain = new BlockChain();
    }

    ChatSession(String host, int port, String name, String publicKeyString, BlockChain blockChain) throws GeneralSecurityException {
        this.host = host;
        this.port = port;
        this.name = name;
        this.rsaSign = new RSASign(publicKeyString);
        this.blockChain = blockChain;
    }

    void send(RSASign rsaSign, String name, String text) throws GeneralSecurityException {
        blockChain.add(rsaSign, name, text, System.currentTimeMillis());
        try {
            Socket socket = new Socket(host, port);
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeUTF(blockChain.get(blockChain.size() - 1).toString());
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    boolean add(Block block) throws GeneralSecurityException {
        if (rsaSign.getVerify(block.text, block.sign)) {
            return blockChain.add(rsaSign, block);
        }
        return false;
    }
}

class BlockChain extends ArrayList<Block> {
    BlockChain() {
    }

    BlockChain(String data) throws BlockParseException {
        String[] line = data.split("\n\n");
        for (String temp : line) {
            add(new Block(temp));
        }
    }

    public String toString() {
        StringJoiner stringJoiner = new StringJoiner("\n\n");
        for (Block block : this) {
            stringJoiner.add(block.toString());
        }
        return stringJoiner.toString();
    }

    public boolean add(RSASign rsaSign, Block block) throws GeneralSecurityException {
        if (size() == 0) {
            return super.add(block);
        } else if (rsaSign.getVerify(get(size() - 1).toString(), block.hash)) {
            return super.add(block);
        }
        return false;
    }

    public void add(RSASign rsaSign, String name, String text, long timestamp) throws GeneralSecurityException {
        super.add(new Block(
                size() == 0 ? "" : rsaSign.getSign(get(size() - 1).toString()),
                rsaSign.getSign(text),
                name,
                text,
                timestamp
        ));
    }
}

class Block {
    String hash;
    String sign;
    String name;
    String text;
    long time;

    Block(String data) throws BlockParseException {
        String[] line = data.split("\n");
        for (String temp : line) {
            String[] kv = temp.split(": ", 2);
            if (kv.length != 2) {
                throw new BlockParseException();
            }
            if (Objects.equals(kv[0], "hash")) {
                hash = kv[1];
            } else if (Objects.equals(kv[0], "sign")) {
                sign = kv[1];
            } else if (Objects.equals(kv[0], "name")) {
                name = kv[1];
            } else if (Objects.equals(kv[0], "text")) {
                text = kv[1];
            } else if (Objects.equals(kv[0], "time")) {
                time = Long.parseLong(kv[1]);
            } else {
                throw new BlockParseException();
            }
        }
    }

    Block(String hash, String sign, String name, String text, long time) {
        this.hash = hash;
        this.sign = sign;
        this.name = name;
        this.text = text;
        this.time = time;
    }

    public String toString() {
        return String.format("hash: %s\nsign: %s\nname: %s\ntext: %s\ntime: %d", hash, sign, name, text, time);
    }
}

class BlockParseException extends Exception {

}