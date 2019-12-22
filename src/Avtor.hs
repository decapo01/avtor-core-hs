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

type CreateAccount = CreateAccountReq -> IO (Either AvtorError Account)
type UpdateAccount = UpdateAccountReq -> IO (Either AvtorError Account)

type RegisterUser = RegisterReq -> IO (Either AvtorError UnverUser)
type VerifyUser   = VerifyReq   -> IO (Either AvtorError User)

type Login  = LoginReq  -> IO (Either AvtorError AuthToken)
type Logout = LogoutReq -> IO (Either AvtorError ())

type Authenticate = AuthReq -> IO (Maybe LoggedInUser)


data AvtorError
  = AccountNotFound
  | AccountAlreadyExists
  | EmailInvalid
  | PasswordInvalid
  | ConfirmPasswordDoesNotMatch
  | PasswordIncorrect
  | UserNotFound
  | UserExists
  | RepoError
  | IpRestricted
  | LoginAttemptsExceeded

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


(...) = flip ($)


data CreateAccountReq
  = CreateAccountReq
  { createAccountReqName    :: Text
  , createAccountReqGenUUID :: IO UUID
  , findAccountByName       :: Text -> IO (Maybe Account)
  , insertAccount           :: Account -> IO (Either AvtorError ())
  }

createAccount :: CreateAccount
createAccount req@CreateAccountReq{..} = do
  maybeAccount <- findAccountByName createAccountReqName
  case maybeAccount of
    Just _  -> return $ Left UserExists
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
  , updateAccountReqFindById       :: AccountId -> IO (Either AvtorError (Maybe Account))
  , findOthersByName               :: AccountId -> Text -> IO (Either AvtorError (Maybe Account))
  , updateAccountReqUpdateAccount  :: Account -> IO (Either AvtorError ())
  }

updateAccount :: UpdateAccount
updateAccount req@UpdateAccountReq{..} = runExceptT $ do
  maybeAccount <- ExceptT $ updateAccountReqFindById $ modifiedAccount..._accountId
  case maybeAccount of
    Nothing -> throwE AccountNotFound
    Just _  -> do
      maybeOtherAccount <- ExceptT $ findOthersByName (modifiedAccount..._accountId) (modifiedAccount...accountName)
      case maybeOtherAccount of
        Just _  -> throwE AccountAlreadyExists
        Nothing -> do
          _ <- ExceptT $ updateAccountReqUpdateAccount modifiedAccount
          return modifiedAccount


data RegisterReq
  = RegisterReq
  { regDto       :: RegisterDto
  , registerReqAccountId :: UUID
  , generateUUID :: IO UUID
  , findByEmail  :: Text      -> IO (Maybe User)
  , savePreUser  :: UnverUser -> IO (Either AvtorError ())
  , sendEmail    :: Text      -> IO (Either AvtorError ())
  }

registerUser :: RegisterUser
registerUser req@RegisterReq{..} = do
  if regDto...rPass /= regDto...rConfirmPass
    then
      return $ Left ConfirmPasswordDoesNotMatch
    else do
      mayUser <- findByEmail $ regDto...rEmail
      case mayUser of
        Just _  -> return $ Left UserExists
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
  , saveUser            :: User      -> IO (Either AvtorError User)
  }

verifyUser :: VerifyUser
verifyUser req = do
  mayUnverifiedUser <- req...findPreuserByToken $ req...vToken
  case mayUnverifiedUser of
    Nothing -> return $ Left UserNotFound
    Just u  -> runExceptT $ do
      let newUser = mapUnverifiedUserToUser u
      ExceptT $ req...saveUser $ newUser


data LoginReq = 
  LoginReq
  { loginReqDto          :: LoginDto
  , ipAddress            :: Text
  , findRestrictedIp     :: Text -> IO (Either AvtorError (Maybe RestrictedIp))
  , findAttempts         :: Text -> IO (Either AvtorError [LoginAttempt])
  , findUserByEmail      :: Text -> IO (Either AvtorError (Maybe User))
  , matchPassword        :: Text -> Text -> Bool
  , createDate           :: IO UTCTime
  , insertAttempt        :: LoginAttempt -> IO (Either AvtorError ())
  , loginReqGenerateUUID :: IO UUID
  }

login :: Login
login req@LoginReq{..} = runExceptT $ do
  maybeBadIp <- ExceptT $ findRestrictedIp ipAddress
  case maybeBadIp of
    Just _ -> throwE IpRestricted
    Nothing -> do
      loginAttempts <- ExceptT $ findAttempts ipAddress
      if Prelude.length loginAttempts > 10
        then
          throwE LoginAttemptsExceeded
        else do
          userOpt <- ExceptT $ findUserByEmail $ loginReqDto...loginDtoEmail
          case userOpt of
            Nothing -> do
              attemptId <- liftIO loginReqGenerateUUID
              now       <- liftIO createDate
              let attempt = LoginAttempt (LoginAttemptId attemptId) ipAddress now
              _ <- ExceptT $ insertAttempt attempt
              throwE UserNotFound
            Just u  ->
              if matchPassword (loginReqDto...loginDtoPass) (u...userPass)
                then
                  return $ AuthToken "todo"
                else do
                  attemptId <- liftIO loginReqGenerateUUID
                  now       <- liftIO createDate
                  let attempt = LoginAttempt (LoginAttemptId attemptId) ipAddress now
                  _ <- ExceptT $ insertAttempt attempt
                  throwE PasswordIncorrect



data LogoutReq = LogoutReq
  { logoutReqAuthToken :: AuthToken
  , destroyAuthToken :: AuthToken -> IO (Either AvtorError ())
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