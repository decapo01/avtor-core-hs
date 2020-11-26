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
  -> Text                        -- IpAddress
  -> (Text -> IO [LoginAttempt]) -- findAllLoginAttempts
  -> (LoginAttempt -> IO ())     -- insertLoginAttempt
  -> (Text -> IO ())             -- insertIpAddress
  -> (Text -> IO (Maybe RestrictedIpId)) -- findBlockedIp
  -> (Text -> IO (Maybe User))  -- findUserByEmail
  -> (Text -> Text -> Bool)     -- checkHashedPassword
  -> (() -> IO Text)            -- generateJwt
  -> IO (Either AvtorError Text)

type SignOut
  =  Text      -- Jwt Session to delete
  -> IO ()

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
  deriving (Show, Generic, Eq)

instance ToJSON   AccountId
instance FromJSON AccountId


newtype VerificationToken
  = VerificationToken
  { verificationToken :: UUID 
  }
  deriving (Show, Generic, Eq)


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
  deriving (Show, Generic, Eq)

newtype AuthToken = AuthToken
  { authToken :: Text
  }
  deriving (Show, Generic, Eq)

newtype UserId
  = UserId
  { _userId :: UUID
  }
  deriving (Generic, Show, Eq)

instance ToJSON UserId
instance FromJSON UserId

data User
  = User
  { userId        :: UserId
  , userEmail     :: Text
  , userPass      :: Text
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
  , unverifiedUserToken     :: VerificationToken
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
  { _loginAttemptId :: UUID
  }
  deriving(Show, Eq, Generic)

data LoginAttempt =
  LoginAttempt
  { loginAttemptId :: LoginAttemptId
  , address         :: Text
  , createdOn       :: UTCTime
  }
  deriving (Show, Eq, Generic)

newtype RestrictedIpId =
  RestrictedIpId
  { restrictedIpId :: UUID
  }
  deriving (Show, Eq)

data RestrictedIp =
  RestrictedIp
  { _restrictedIpId :: RestrictedIpId
  , restrictedIp    :: Text
  }
  deriving (Show, Eq)


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

verifyUser :: VerifyUser
verifyUser token findUserByVerificationToken insertUser = runExceptT $ do
  maybeUser <- liftIO $ findUserByVerificationToken token
  case maybeUser of
    Nothing -> throwE UserNotFound
    Just unverifiedUser ->
      ExceptT $ insertUser $ mapUnverifiedUserToUser unverifiedUser



data SignInDeps
  = SignInDeps
  { signInDepsFindAllLoginAttemptsByIp :: Text -> IO [LoginAttempt]
  , signInDepsInsertLoginAttempt       :: LoginAttempt -> IO ()
  , signInDepsGenerateRestrictedIpUuid :: () -> IO UUID
  , signInDepsInsertRestrictedIp       :: RestrictedIp -> IO ()
  , signInDepsFindRestrictedIpByIp     :: Text -> IO (Maybe RestrictedIp)
  , signInDepsFindUserByUsername       :: Text -> IO (Maybe User)
  , signInDepsCheckIfPasswordsMatch    :: Text -> Text -> Bool
  , signInDepsGenerateJwt              :: () -> IO Text
  }

signIn :: SignInDeps
       -> SignInDto
       -> Text
       -> IO (Either AvtorError Text)
signIn deps@SignInDeps{..} dto ipAddress = runExceptT $ do
  maybeBlockedIp <- liftIO $ signInDepsFindRestrictedIpByIp ipAddress
  case maybeBlockedIp of
    Just _ -> throwE IpRestricted
    Nothing -> do
      loginAttempts <- liftIO $ signInDepsFindAllLoginAttemptsByIp ipAddress
      if (Prelude.length loginAttempts) >= 10 -- todo: maybe make this configurable
        then do
          restrictedIpUuid <- liftIO $ signInDepsGenerateRestrictedIpUuid ()
          _ <- liftIO $ signInDepsInsertRestrictedIp $ RestrictedIp (RestrictedIpId restrictedIpUuid) ipAddress
          throwE LoginAttemptsExceeded
        else do
          maybeUser <- liftIO $ signInDepsFindUserByUsername (signInDtoEmail dto)
          case maybeUser of
            Nothing   -> throwE UserNotFound
            Just user -> do
              if signInDepsCheckIfPasswordsMatch (signInDtoPassword dto) (userPass user)
                then do
                  jwt <- liftIO $ signInDepsGenerateJwt ()
                  return jwt
                else
                  throwE PasswordIncorrect


data AuthReq = AuthReq
  { authReqToken        :: AuthToken
  , createUserFromToken :: AuthToken -> IO (Maybe LoggedInUser)
  }

authenticate :: Authenticate
authenticate req =
  req...createUserFromToken $ req...authReqToken


mapSignUpDtoToUnverifiedUser :: UUID ->   UUID -> UUID -> SignUpDto -> UnverifiedUser
mapSignUpDtoToUnverifiedUser    accountId uuid    token   dto =
  UnverifiedUser
  { unverifiedUserId        = UserId { _userId = uuid }
  , unverifiedUserEmail     = (signUpDtoEmail dto)
  , unverifiedUserPassword  = (signUpDtoPassword dto)
  , unverifiedUserToken     = VerificationToken token
  , unverifiedUserAccountId = AccountId accountId
  }

mapRegistrationDataToUnverifiedUser :: UUID -> UUID -> UUID -> RegisterDto -> UnverifiedUser
mapRegistrationDataToUnverifiedUser uuid accountId token dto =
  UnverifiedUser 
  { unverifiedUserId        = UserId uuid
  , unverifiedUserToken     = VerificationToken token
  , unverifiedUserAccountId = AccountId accountId
  , unverifiedUserEmail     = rEmail dto
  , unverifiedUserPassword  = rPass dto 
  }


mapUnverifiedUserToUser :: UnverifiedUser -> User
mapUnverifiedUserToUser unverifiedUser =
  User 
  { userId        = unverifiedUserId unverifiedUser
  , userEmail     = unverifiedUserEmail unverifiedUser
  , userPass      = unverifiedUserPassword unverifiedUser
  , userAccountId = unverifiedUserAccountId unverifiedUser
  }

mapUserToLoginUser :: User -> LoggedInUser
mapUserToLoginUser user =
  LoggedInUser
  { loggedInUserId    = userId user
  , loggedInUserEmail = userEmail user
  }