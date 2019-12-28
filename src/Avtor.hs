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

type SignUp 
  =  SignUpDto
  -> (Text -> IO (Maybe User))                     -- findUserById
  -> (Text -> IO (Either AvtorError Text))         -- hashPassword
  -> (() -> IO UUID)
  -> (() -> IO UUID)                               -- genereateToken
  -> (() -> IO UUID)                               -- generateAccountId
  -> (UnverifiedUser -> IO (Either AvtorError ())) -- insertUser
  -> (Text -> IO (Either AvtorError ()))           -- sendEmail
  -> (UserId -> IO (Either AvtorError ()))         -- removeUserIfEmailFails
  -> IO (Either AvtorError ())                     -- avtor error

type VerifyUser
  =  VerificationToken
  -> (VerificationToken -> IO (Maybe UnverifiedUser))
  -> (User -> IO (Either AvtorError ()))
  -> IO (Either AvtorError ())

type SignIn
  =  SignInDto
  -> (Text -> IO (Maybe User))  -- findUserByEmail
  -> (Text -> Text -> Bool)     -- checkHashedPassword
  -> (() -> IO Text)            -- generateJwt
  -> IO (Either AvtorError Text)

type SignOut
  = Text      -- Jwt Session to delete

type CreateAccount = CreateAccountReq -> IO (Either AvtorError Account)
type UpdateAccount = UpdateAccountReq -> IO (Either AvtorError Account)

type RegisterUser = RegisterReq -> IO (Either AvtorError UnverifiedUser)
-- type VerifyUser   = VerifyReq   -> IO (Either AvtorError User)

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
  { _accountId :: UUID
  }
  deriving (Show,Generic)

instance ToJSON   AccountId
instance FromJSON AccountId


newtype VerificationToken
  = VerificationToken
  { verificationToke :: UUID 
  }
  deriving (Show,Generic)


data SignUpDto
  = SignUpDto
  { signUpDtoEmail           :: Text
  , signUpDtoPassword        :: Text
  , signUpDtoConfirmPassword :: Text
  , signUpDtoAccountId       :: Maybe UUID
  }
  deriving (Show)

data SignInDto
  = SignInDto
  { signInDtoEmail    :: Text
  , signInDtoPassword :: Text
  }

data Account
  = Account
  { accountId   :: AccountId
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
  { _userId :: UUID
  }
  deriving (Generic,Show)

instance ToJSON UserId
instance FromJSON UserId

data User
  = User
  { userId   :: UserId
  , userEmail :: Text
  , userPass  :: Text
  , userAccountId :: AccountId
  }
  deriving (Generic,Show)

instance ToJSON User
instance FromJSON User

data UnverifiedUser
  = UnverifiedUser
  { unverifiedUserId        :: UserId
  , unverifiedUserEmail     :: Text
  , unverifiedUserPassword  :: Text
  , unverifiedUserToken     :: VerToken
  , unverifiedUserAccountId :: AccountId
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



signUp :: SignUp
signUp dto findUserById hashPassword generateUuid generateToken generateAccountId insertUser sendEmail removeUserIfEmailFails = runExceptT $ do
  maybeUser <- liftIO $ findUserById (signUpDtoEmail dto)
  case maybeUser of
    Just _ -> throwE UserExists
    Nothing -> do
      uuid      <- liftIO  $ generateUuid ()
      hash      <- ExceptT $ hashPassword (signUpDtoPassword dto)
      token     <- liftIO  $ generateToken ()
      accountId <- liftIO  $ accountIdIO
      _         <- ExceptT $ insertUser $ mapSignUpDtoToUnverifiedUser accountId uuid token dto
      emailSent <- liftIO  $ sendEmail (signUpDtoEmail dto)
      case emailSent of
        Left _  -> ExceptT $ removeUserIfEmailFails $ UserId uuid
        Right _ -> return ()
  where
    accountIdIO = case (signUpDtoAccountId dto) of
      Just accountUuid -> return accountUuid
      Nothing          -> generateAccountId ()


mapSignUpDtoToUnverifiedUser :: UUID -> UUID -> UUID -> SignUpDto -> UnverifiedUser
mapSignUpDtoToUnverifiedUser accountId uuid token dto =
  UnverifiedUser
  { unverifiedUserId        = UserId { _userId = uuid }
  , unverifiedUserEmail     = (signUpDtoEmail dto)
  , unverifiedUserPassword  = (signUpDtoPassword dto)
  , unverifiedUserToken     = VerToken token
  , unverifiedUserAccountId = AccountId accountId
  }

verifyUser :: VerifyUser
verifyUser token findUserByVerificationToken insertUser = runExceptT $ do
  maybeUser <- liftIO $ findUserByVerificationToken token
  case maybeUser of
    Nothing -> throwE UserNotFound
    Just unverifiedUser ->
      ExceptT $ insertUser $ mapUnverifiedUserToUser unverifiedUser


signIn :: SignIn
signIn dto findUserByEmail passwordsMatch generateJwt = do
  maybeUser <- findUserByEmail (signInDtoEmail dto)
  case maybeUser of
    Nothing   -> return $ Left UserNotFound
    Just user -> do
      jwt <- generateJwt ()
      return $ Right jwt

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
  maybeAccount <- ExceptT $ updateAccountReqFindById $ modifiedAccount...accountId
  case maybeAccount of
    Nothing -> throwE AccountNotFound
    Just _  -> do
      maybeOtherAccount <- ExceptT $ findOthersByName (modifiedAccount...accountId) (modifiedAccount...accountName)
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
  , findByEmail  :: Text           -> IO (Maybe User)
  , savePreUser  :: UnverifiedUser -> IO (Either AvtorError ())
  , sendEmail    :: Text           -> IO (Either AvtorError ())
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
  , findPreuserByToken  :: VerToken  -> IO (Maybe UnverifiedUser)
  , saveUser            :: User      -> IO (Either AvtorError User)
  }

-- verifyUser :: VerifyUser
-- verifyUser verificationToken findByVerificationToken insertUser = do
--   mayUnverifiedUser <- findByVerificationToken $ verificationToken
--   case mayUnverifiedUser of
--     Nothing -> return $ Left UserNotFound
--     Just u  -> runExceptT $ do
--       let newUser = mapUnverifiedUserToUser u
--       ExceptT $ insertUser $ newUser


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


mapRegistrationDataToUnverifiedUser :: UUID -> UUID -> UUID -> RegisterDto -> UnverifiedUser
mapRegistrationDataToUnverifiedUser uuid accountId token dto =
  UnverifiedUser 
  { unverifiedUserId        = UserId uuid
  , unverifiedUserToken     = VerToken token
  , unverifiedUserAccountId = AccountId accountId
  , unverifiedUserEmail     = dto...rEmail
  , unverifiedUserPassword  = dto...rPass 
  }


mapUnverifiedUserToUser :: UnverifiedUser -> User
mapUnverifiedUserToUser unverifiedUser =
  User 
  { userId        = unverifiedUser...unverifiedUserId
  , userEmail     = unverifiedUser...unverifiedUserEmail
  , userPass      = unverifiedUser...unverifiedUserPassword
  , userAccountId = unverifiedUser...unverifiedUserAccountId
  }

mapUserToLoginUser :: User -> LoggedInUser
mapUserToLoginUser user =
  LoggedInUser
  { loggedInUserId    = user...userId
  , loggedInUserEmail = user...userEmail
  }