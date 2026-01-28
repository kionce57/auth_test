# Google OAuth 設定教學

本教學將指導你如何在 Google Cloud Platform (GCP) 設定 OAuth 2.0，並在本專案中使用你自己的金鑰進行測試。

## 目錄

1. [前置準備](#前置準備)
2. [GCP 專案設定](#gcp-專案設定)
3. [OAuth 同意畫面設定](#oauth-同意畫面設定)
4. [建立 OAuth 憑證](#建立-oauth-憑證)
5. [設定本地環境](#設定本地環境)
6. [測試 Google 登入](#測試-google-登入)
7. [常見問題排解](#常見問題排解)

---

## 前置準備

- Google 帳號
- 本專案已設定完成（後端、前端、資料庫都能正常運行）
- 已執行資料庫遷移：`uv run alembic upgrade head`

---

## GCP 專案設定

### Step 1：進入 Google Cloud Console

1. 打開瀏覽器，前往 [Google Cloud Console](https://console.cloud.google.com/)
2. 使用你的 Google 帳號登入

### Step 2：建立新專案

1. 點擊頁面左上角的專案選擇器（通常顯示 "Select a project" 或現有專案名稱）
2. 在彈出視窗中點擊 **NEW PROJECT**
3. 輸入專案資訊：
   - **Project name**: `auth-test-dev`（或任何你喜歡的名稱）
   - **Location**: 保持預設即可
4. 點擊 **CREATE**
5. 等待專案建立完成（約 30 秒），系統會自動切換到新專案

---

## OAuth 同意畫面設定

> [!IMPORTANT]
> 這一步驟必須先完成，才能建立 OAuth 憑證。

### Step 3：設定 OAuth 同意畫面

1. 在左側選單中，找到 **APIs & Services** → **OAuth consent screen**
2. 選擇 **User Type**：
   - **External**：選擇這個（允許任何 Google 帳號登入）
3. 點擊 **CREATE**

### Step 4：填寫應用程式資訊

#### App information

| 欄位               | 填寫內容                  |
| ------------------ | ------------------------- |
| App name           | `Auth Test`（或任何名稱） |
| User support email | 你的 Gmail 地址           |

#### App logo（可選）

可以跳過，不影響功能。

#### App domain（可選）

開發階段可以跳過。

#### Developer contact information

| 欄位            | 填寫內容        |
| --------------- | --------------- |
| Email addresses | 你的 Gmail 地址 |

點擊 **SAVE AND CONTINUE**

### Step 5：設定 Scopes（權限範圍）

1. 點擊 **ADD OR REMOVE SCOPES**
2. 勾選以下三個基本權限：
   - `.../auth/userinfo.email` - 查看使用者 email
   - `.../auth/userinfo.profile` - 查看使用者基本資料
   - `openid` - 使用 OpenID Connect 認證
3. 點擊 **UPDATE**
4. 點擊 **SAVE AND CONTINUE**

### Step 6：新增測試使用者

> [!WARNING]
> 因為 App 處於「Testing」狀態，只有加入的測試使用者可以登入！

1. 點擊 **+ ADD USERS**
2. 輸入你要用來測試的 Gmail 地址
3. 點擊 **ADD**
4. 點擊 **SAVE AND CONTINUE**

### Step 7：確認設定

檢查摘要頁面，確認資訊正確後點擊 **BACK TO DASHBOARD**

---

## 建立 OAuth 憑證

> [!NOTE]
> 完成 OAuth 同意畫面設定後，接下來要建立實際的 OAuth 憑證（Client ID 和 Client Secret）。
> 這是讓你的應用程式能夠與 Google 進行 OAuth 認證的關鍵步驟。

### Step 8：進入 Credentials 頁面

1. 在左側選單中，進入 **APIs & Services** → **Credentials**
2. 你會看到目前專案中的所有憑證（目前應該是空的）

### Step 9：建立 OAuth Client ID

1. 點擊頁面上方的 **+ CREATE CREDENTIALS** 按鈕
2. 在下拉選單中選擇 **OAuth client ID**

> [!IMPORTANT]
> 如果你看到「To create an OAuth client ID, you must first configure your consent screen」的提示，
> 代表你尚未完成 OAuth 同意畫面設定，請回到 Step 3 完成設定。

### Step 10：選擇應用程式類型（關鍵步驟）

在「Create OAuth client ID」頁面：

1. **Application type**：從下拉選單選擇 **「Web application」**

   > 這是網頁應用程式，所以必須選擇 Web application。
   > 其他選項（如 Desktop app、Android、iOS）用於不同類型的應用程式。

2. **Name**：輸入 `Auth Test Web Client`（或任何你喜歡的名稱）

### Step 11：設定授權來源與重新導向 URI（最關鍵步驟）

#### Authorized JavaScript origins（授權的 JavaScript 來源）

這是允許發起 OAuth 請求的前端網址。

1. 點擊 **+ ADD URI**
2. 輸入：
   ```
   http://localhost:5173
   ```

#### Authorized redirect URIs（授權的重新導向 URI）

> [!CAUTION]
> **這是最容易出錯的設定！** Redirect URI 必須與後端程式碼中的設定 **完全一致**，
> 包括 protocol (http/https)、port、路徑，甚至結尾不能多一個斜線。

1. 點擊 **+ ADD URI**
2. **精確輸入**以下網址：
   ```
   http://localhost:8000/api/v2/sessions/google/callback
   ```

**Redirect URI 說明：**
| 組成部分 | 值 | 說明 |
|---------|-----|------|
| Protocol | `http://` | 開發環境用 http |
| Host | `localhost` | 本機 |
| Port | `8000` | 後端服務的 port |
| Path | `/api/v2/sessions/google/callback` | 後端 OAuth callback endpoint |

### Step 12：建立並取得憑證

1. 確認所有設定正確後，點擊 **CREATE**
2. 成功後會彈出視窗顯示你的憑證：

   ```
   ┌─────────────────────────────────────────────────────────┐
   │  OAuth client created                                   │
   │                                                         │
   │  Client ID:                                             │
   │  123456789-xxxxxxxxxx.apps.googleusercontent.com        │
   │                                                         │
   │  Client Secret:                                         │
   │  GOCSPX-xxxxxxxxxx                                      │
   │                                                         │
   │  [Download JSON]              [OK]                      │
   └─────────────────────────────────────────────────────────┘
   ```

3. **立即複製這兩個值！**（特別是 Client Secret，之後無法再次查看完整值）
4. 點擊 **OK** 關閉視窗

> [!TIP]
> 如果你忘記複製，可以回到 Credentials 頁面，點擊你建立的 OAuth Client，
> 然後點擊「DOWNLOAD JSON」下載憑證檔案，或直接在頁面上查看。

---

## 設定本地環境

### Step 13：更新 .env 檔案

1. 打開專案中的 `backend/.env` 檔案
2. 新增或更新以下設定：

```env
# Google OAuth 設定
GOOGLE_CLIENT_ID=你的Client ID
GOOGLE_CLIENT_SECRET=你的Client Secret
```

**範例：**

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/auth_test
SECRET_KEY=dev-secret-key-change-in-production-2024
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# Google OAuth
GOOGLE_CLIENT_ID=123456789-abc123xyz.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abcdefghijk123456
```

### Step 14：重啟後端服務

環境變數變更後需要重啟後端才會生效：

```bash
# 停止目前運行的後端（Ctrl+C）
# 重新啟動
cd backend
uv run uvicorn app.main:app --reload --port 8000
```

---

## 測試 Google 登入

### Step 15：執行測試

1. 確保所有服務都在運行：
   - 資料庫：`docker compose up -d`
   - 後端：`uv run uvicorn app.main:app --reload --port 8000`
   - 前端：`npm run dev`

2. 打開瀏覽器，前往 http://localhost:5173/login

3. 點擊「**使用 Google 登入**」按鈕

4. 在 Google 登入頁面選擇你的帳號

5. 如果成功，你會被導向主頁面並看到登入狀態

### 測試驗收標準

- [ ] 點擊 Google 登入按鈕後，成功跳轉到 Google 授權頁面
- [ ] 選擇帳號後，成功跳轉回應用程式
- [ ] 登入後可以看到使用者資訊（email）
- [ ] 登出後再次登入，流程正常
- [ ] 在 Google 授權頁面點「取消」，會看到友善的錯誤訊息

---

## 常見問題排解

### 錯誤：「已封鎖存取權：只能在所屬機構內使用」

**原因**：OAuth 同意畫面設定為 Internal（內部），或是你沒有加入測試使用者。

**解決方法**：

1. 確認你選擇的是 **External**
2. 在 OAuth consent screen → Test users 中加入你的 Gmail

---

### 錯誤：「Error 400: redirect_uri_mismatch」

**原因**：GCP 設定的 Redirect URI 和後端設定不一致。

**解決方法**：
確認 GCP 的 Authorized redirect URIs 完全符合：

```
http://localhost:8000/api/v2/sessions/google/callback
```

注意：不能有結尾斜線、大小寫必須一致。

---

### 錯誤：「登入請求已過期，請重新嘗試」

**原因**：State token 已過期（超過 5 分鐘）或後端重啟導致 state 遺失。

**解決方法**：
重新點擊 Google 登入按鈕即可。

---

### 錯誤：「oauth_failed」

**原因**：Google API 回傳錯誤，可能是 Client ID 或 Client Secret 設定錯誤。

**解決方法**：

1. 檢查 `.env` 中的 `GOOGLE_CLIENT_ID` 和 `GOOGLE_CLIENT_SECRET` 是否正確
2. 確認沒有多餘的空格或換行符號
3. 重啟後端服務

---

### 無法登入，但沒有錯誤訊息

**解決方法**：

1. 打開瀏覽器開發者工具（F12）
2. 查看 Console 和 Network 分頁
3. 檢查後端 Terminal 是否有錯誤訊息

---

## 安全提醒

> [!CAUTION]
>
> - **絕對不要**將 `.env` 檔案提交到 Git
> - **絕對不要**在公開場合分享你的 Client Secret
> - 每個開發者應該使用自己的 GCP 專案和憑證

---

## 延伸閱讀

- [Google OAuth 2.0 官方文件](https://developers.google.com/identity/protocols/oauth2)
- [OpenID Connect 規格](https://openid.net/connect/)
- [本專案 AUTH_TUTORIAL.md](./AUTH_TUTORIAL.md)
