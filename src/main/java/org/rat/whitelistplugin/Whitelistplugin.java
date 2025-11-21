package org.rat.whitelistplugin;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;
import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;
public class Whitelistplugin extends JavaPlugin {
    private String remoteUrl;
    private String authKey;
    private File localWhitelist;
    private boolean enabled;
    @Override
    public void onEnable() {
        saveDefaultConfig();
        remoteUrl = getConfig().getString("url", "https://example.com/whitelist.json");
        authKey = getConfig().getString("auth_key", "authkeyhere"); // default fallback
        enabled = getConfig().getBoolean("enabled", true);
        int pollInterval = getConfig().getInt("poll_interval_seconds", 15);
        localWhitelist = new File(Bukkit.getWorldContainer(), "whitelist.json");
        Bukkit.getScheduler().runTaskTimerAsynchronously(
                this,
                this::pollRemoteWhitelist,
                0L,
                20L * pollInterval
        );
        getLogger().info("WhitelistSync loaded. Status: " + (enabled ? "ENABLED" : "DISABLED"));
        getLogger().info("Polling " + remoteUrl + " every " + pollInterval + "s.");
    }
    private void pollRemoteWhitelist() {
        if (!enabled) return;
        try {
            String remoteJson = fetchRemoteJson();
            if (remoteJson == null) return;
            String localJson = Files.readString(localWhitelist.toPath());
            String remoteHash = sha256(remoteJson);
            String localHash = sha256(localJson);
            if (!remoteHash.equals(localHash)) {
                Files.writeString(localWhitelist.toPath(), remoteJson, StandardCharsets.UTF_8);
                Bukkit.getScheduler().runTask(
                        this,
                        () -> Bukkit.dispatchCommand(
                                Bukkit.getConsoleSender(),
                                "whitelist reload"
                        )
                );
            }
        } catch (Exception ex) {
            getLogger().warning("Whitelist sync failed: " + ex.getMessage());
        }
    }
    private String fetchRemoteJson() {
        try {
            URL url = new URL(remoteUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("Authorization", "Bearer " + authKey);
            int code = conn.getResponseCode();
            if (code != 200) {
                getLogger().warning("Remote returned HTTP " + code);
                return null;
            }
            InputStream in = conn.getInputStream();
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            JsonElement parsed = JsonParser.parseString(text);
            if (!parsed.isJsonArray()) {
                getLogger().warning("Remote returned non-array JSON.");
                return null;
            }
            return text;
        } catch (Exception ex) {
            getLogger().warning("Failed fetching remote whitelist: " + ex.getMessage());
            return null;
        }
    }
    private String sha256(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(s.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }
    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!command.getName().equalsIgnoreCase("whitelistplugin")) {
            return false;
        }
        if (!sender.hasPermission("whitelistplugin.toggle")) {
            sender.sendMessage("§cYou don't have permission to use this command.");
            return true;
        }
        if (args.length != 1) {
            sender.sendMessage("§cUsage: /whitelistplugin <allow|deny>");
            return true;
        }
        if (args[0].equalsIgnoreCase("allow")) {
            enabled = true;
            getConfig().set("enabled", true);
            saveConfig();
            sender.sendMessage("§aWhitelist sync enabled!");
            getLogger().info(sender.getName() + " enabled whitelist sync.");
            return true;
        } else if (args[0].equalsIgnoreCase("deny")) {
            enabled = false;
            getConfig().set("enabled", false);
            saveConfig();
            sender.sendMessage("§cWhitelist sync disabled!");
            getLogger().info(sender.getName() + " disabled whitelist sync.");
            return true;
        } else {
            sender.sendMessage("§cUsage: /whitelistplugin <allow|deny>");
            return true;
        }
    }
}