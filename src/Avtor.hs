{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE RecordWildCards   #-}
module Avtor where

import           Data.Text
import qualified Data.Text as T
import           Data.UUID
import           Data.UUID.V4
import           Control.Monad.IO.Class (liftIO)
import           GHC.Generics
import           Data.Aeson
import           Control.Monad.Trans.Except
import           Control.Monad
import           Data.Time (UTCTime)

type CreateAccount = CreateAccountReq -> IO (Either Text Account)
type UpdateAccount = UpdateAccountReq -> IO (Either Text Account)

type RegisterUser = RegisterReq -> IO (Either Text UnverUser)
type VerifyUser   = VerifyReq   -> IO (Either Text User)

type Login  = LoginReq  -> IO (Either Text AuthToken)
type Logout = LogoutReq -> IO (Either Text ())

type Authenticate = AuthReq -> IO (Maybe LoggedInUser)


newtype AccountId
  = AccountId
  { accountId :: UUID
  }
  deriving (Show,Generic)

instance ToJSON   AccountId
instance FromJSON AccountId


data Account
  = Account
  { _accountId  :: AccountId
  , accountName :: Text
  }
  deriving (Show)

newtype VerToken
  = VerToken
  { verToken :: UUID
  }
  deriving (Show,Generic)

newtype AuthToken = AuthToken
  { authToken :: Text
  }
  deriving (Show,Generic)

newtype UserId
  = UserId
  { userId :: UUID
  }
  deriving (Generic,Show)

instance ToJSON UserId
instance FromJSON UserId

data User
  = User
  { _userId   :: UserId
  , userEmail :: Text
  , userPass  :: Text
  , userAccountId :: AccountId
  }
  deriving (Generic,Show)

instance ToJSON User
instance FromJSON User

data UnverUser
  = UnverUser
  { uvUserId    :: UserId
  , uvEmail     :: Text
  , uvPass      :: Text
  , uvToken     :: VerToken
  , uvAccountId :: AccountId
  }

data LoggedInUser
  = LoggedInUser
  { loggedInUserId    :: UserId
  , loggedInUserEmail :: Text
  }

data RegisterDto
  = RegisterDto
  { rEmail :: Text
  , rPass  :: Text
  , rConfirmPass :: Text
  }
  deriving (Show)

data LoginDto
  = LoginDto
  { loginDtoEmail :: Text
  , loginDtoPass  :: Text
  }
  deriving (Show)

data LogoutDto = LogoutDto

newtype LoginAttemptId =
  LoginAttemptId
  { loginAttemptId :: UUID
  }
  deriving(Show)

data LoginAttempt =
  LoginAttempt
  { _loginAttemptId :: LoginAttemptId
  , address         :: Text
  , createdOn       :: UTCTime
  }
  deriving (Show)

newtype RestrictedIpId =
  RestrictedIpId
  { restrictedIpId :: UUID
  }
  deriving (Show)

data RestrictedIp =
  RestrictedIp
  { _restrictedIpId :: RestrictedIpId
  , restrictedIp    :: Text
  }
  deriving (Show)

(...) =  flip ($)


data CreateAccountReq
  = CreateAccountReq
  { createAccountReqName    :: Text
  , createAccountReqGenUUID :: IO UUID
  , findAccountByName       :: Text -> IO (Maybe Account)
  , insertAccount           :: Account -> IO (Either Text ())
  }

createAccount :: CreateAccount
createAccount req@CreateAccountReq{..} = do
  maybeAccount <- findAccountByName createAccountReqName
  case maybeAccount of
    Just _  -> return $ Left "Account Exists"
    Nothing -> do
      uuid <- createAccountReqGenUUID
      let account = Account (AccountId uuid) createAccountReqName
      accountInsertRes <- insertAccount account
      case accountInsertRes of
        Left e  -> return $ Left e
        Right _ -> return $ Right account


data UpdateAccountReq
  = UpdateAccountReq
  { modifiedAccount                :: Account
  , updateAccountReqFindById       :: AccountId -> IO (Either Text (Maybe Account))
  , findOthersByName               :: AccountId -> Text -> IO (Either Text (Maybe Account))
  , updateAccountReqUpdateAccount  :: Account -> IO (Either Text ())
  }

updateAccount :: UpdateAccount
updateAccount req@UpdateAccountReq{..} = runExceptT $ do
  maybeAccount <- ExceptT $ updateAccountReqFindById $ modifiedAccount..._accountId
  case maybeAccount of
    Nothing -> throwE "Account does not exist"
    Just _  -> do
      maybeOtherAccount <- ExceptT $ findOthersByName (modifiedAccount..._accountId) (modifiedAccount...accountName)
      case maybeOtherAccount of
        Just _  -> throwE "Account by this name currently exists"
        Nothing -> do
          _ <- ExceptT $ updateAccountReqUpdateAccount modifiedAccount
          return modifiedAccount


data RegisterReq
  = RegisterReq
  { regDto       :: RegisterDto
  , registerReqAccountId :: UUID
  , generateUUID :: IO UUID
  , findByEmail  :: Text      -> IO (Maybe User)
  , savePreUser  :: UnverUser -> IO (Either Text ())
  , sendEmail    :: Text      -> IO (Either Text ())
  }

registerUser :: RegisterUser
registerUser req@RegisterReq{..} = do
  if regDto...rPass /= regDto...rConfirmPass
    then
      return $ Left "Passwords do not match"
    else do
      mayUser <- findByEmail $ regDto...rEmail
      case mayUser of
        Just _  -> return $ Left "User Exists"
        Nothing -> runExceptT $ do
          emailSentRes <- ExceptT $ sendEmail $ regDto...rEmail
          uuid         <- liftIO generateUUID
          token        <- liftIO generateUUID
          let unUser    = mapRegistrationDataToUnverifiedUser uuid token registerReqAccountId regDto
          savedUser    <- ExceptT $ savePreUser $ unUser
          return $ 
            unUser


data VerifyReq
  = VerifyReq
  { vToken              :: VerToken
  , findPreuserByToken  :: VerToken  -> IO (Maybe UnverUser)
  , saveUser            :: User      -> IO (Either Text User)
  }

verifyUser :: VerifyUser
verifyUser req = do
  mayUnverifiedUser <- req...findPreuserByToken $ req...vToken
  case mayUnverifiedUser of
    Nothing -> return $ Left "Unverified user could not be found"
    Just u  -> runExceptT $ do
      let newUser = mapUnverifiedUserToUser u
      ExceptT $ req...saveUser $ newUser


data LoginReq = 
  LoginReq
  { loginReqDto          :: LoginDto
  , ipAddress            :: Text
  , findRestrictedIp     :: Text -> IO (Either Text (Maybe RestrictedIp))
  , findAttempts         :: Text -> IO (Either Text [LoginAttempt])
  , findUserByEmail      :: Text -> IO (Either Text (Maybe User))
  , matchPassword        :: Text -> Text -> Bool
  , createDate           :: IO UTCTime
  , insertAttempt        :: LoginAttempt -> IO (Either Text ())
  , loginReqGenerateUUID :: IO UUID
  }

login :: Login
login req@LoginReq{..} = runExceptT $ do
  maybeBadIp    <- ExceptT $ findRestrictedIp ipAddress
  case maybeBadIp of
    Just _ -> throwE "Restricted Ip Attempt"
    Nothing -> do
      loginAttempts <- ExceptT $ findAttempts ipAddress
      guard $ (Prelude.length loginAttempts) > 10 -- figure out how to throw error here
      userOpt       <- ExceptT $ findUserByEmail $ loginReqDto...loginDtoEmail
      case userOpt of
        Nothing -> do
          attemptId <- liftIO loginReqGenerateUUID
          now       <- liftIO createDate
          let attempt = LoginAttempt (LoginAttemptId attemptId) ipAddress now
          _ <- ExceptT $ insertAttempt attempt
          throwE "User not found"
        Just u  ->
          if matchPassword (loginReqDto...loginDtoPass) (u...userPass)
            then
              return $ AuthToken "todo"
            else do
              attemptId <- liftIO loginReqGenerateUUID
              now       <- liftIO createDate
              let attempt = LoginAttempt (LoginAttemptId attemptId) ipAddress now
              _ <- ExceptT $ insertAttempt attempt
              throwE "Passwords do not match"



data LogoutReq = LogoutReq
  { logoutReqAuthToken :: AuthToken
  , destroyAuthToken :: AuthToken -> IO (Either Text ())
  }

logout :: Logout
logout req = do
  req...destroyAuthToken $ req...logoutReqAuthToken


data AuthReq = AuthReq
  { authReqToken        :: AuthToken
  , createUserFromToken :: AuthToken -> IO (Maybe LoggedInUser)
  }

authenticate :: Authenticate
authenticate req =
  req...createUserFromToken $ req...authReqToken


mapRegistrationDataToUnverifiedUser :: UUID -> UUID -> UUID -> RegisterDto -> UnverUser
mapRegistrationDataToUnverifiedUser uuid accountId token dto =
  UnverUser 
  { uvUserId = UserId uuid
  , uvToken  = VerToken token
  , uvAccountId = AccountId accountId
  , uvEmail  = dto...rEmail
  , uvPass   = dto...rPass 
  }


mapUnverifiedUserToUser :: UnverUser -> User
mapUnverifiedUserToUser unverUser =
  User 
  { _userId   = unverUser...uvUserId
  , userEmail = unverUser...uvEmail
  , userPass  = unverUser...uvPass
  , userAccountId = unverUser...uvAccountId
  }

mapUserToLoginUser :: User -> LoggedInUser
mapUserToLoginUser user =
  LoggedInUser
  { loggedInUserId    = user..._userId
  , loggedInUserEmail = user...userEmail
  }