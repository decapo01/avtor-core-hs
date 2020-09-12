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

verifyUser :: VerifyUser
verifyUser token findUserByVerificationToken insertUser = runExceptT $ do
  maybeUser <- liftIO $ findUserByVerificationToken token
  case maybeUser of
    Nothing -> throwE UserNotFound
    Just unverifiedUser ->
      ExceptT $ insertUser $ mapUnverifiedUserToUser unverifiedUser



signIn :: SignIn
signIn dto ipAddress findAllLoginAttempts insertLoginAttempt insertRestrictedIp findBlockedIp findUserByEmail passwordsMatch generateJwt = runExceptT $ do
  maybeBlockedIp <- liftIO $ findBlockedIp ipAddress
  case maybeBlockedIp of
    Just _ -> throwE IpRestricted
    Nothing -> do
      loginAttempts <- liftIO $ findAllLoginAttempts ipAddress
      if (Prelude.length loginAttempts) >= 10
        then do
          _ <- liftIO $ insertRestrictedIp ipAddress
          throwE LoginAttemptsExceeded
        else do
          maybeUser <- liftIO $ findUserByEmail (signInDtoEmail dto)
          case maybeUser of
            Nothing   -> throwE UserNotFound
            Just user -> do
              if passwordsMatch (signInDtoPassword dto) (userPass user)
                then do
                  jwt <- liftIO $ generateJwt ()
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
  , unverifiedUserToken     = VerToken token
  , unverifiedUserAccountId = AccountId accountId
  }

mapRegistrationDataToUnverifiedUser :: UUID -> UUID -> UUID -> RegisterDto -> UnverifiedUser
mapRegistrationDataToUnverifiedUser uuid accountId token dto =
  UnverifiedUser 
  { unverifiedUserId        = UserId uuid
  , unverifiedUserToken     = VerToken token
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