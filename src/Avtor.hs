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

type RegisterUser = RegisterReq -> IO (Either Text UnverUser)
type VerifyUser   = VerifyReq   -> IO (Either Text User)

type Login  = LoginReq  -> IO (Either Text AuthToken)
type Logout = LogoutReq -> IO (Either Text ())

type Authenticate = AuthReq -> IO (Maybe LoggedInUser)

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
  }
  deriving (Generic,Show)

instance ToJSON User
instance FromJSON User

data UnverUser
  = UnverUser
  { uvUserId :: UserId
  , uvEmail  :: Text
  , uvPass   :: Text
  , uvToken  :: VerToken
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

data RegisterReq
  = RegisterReq
  { regDto      :: RegisterDto
  , findByEmail :: Text -> IO (Maybe User)
  , savePreUser :: UnverUser -> IO (Either Text ())
  , sendEmail   :: Text -> IO (Either Text ())
  }

(...) =  flip ($)

registerUser :: RegisterUser
registerUser req = do
  if req...regDto...rPass /= req...regDto...rConfirmPass
    then
      return $ Left "Passwords do not match"
    else do
      mayUser <- req...findByEmail $ req...regDto...rEmail
      case mayUser of
        Just _  -> return $ Left "User Exists"
        Nothing -> runExceptT $ do
          emailSentRes <- ExceptT $ req...sendEmail $ req...regDto...rEmail
          uuid         <- liftIO nextRandom
          token        <- liftIO nextRandom
          let unUser    = mapRegistrationDataToUnverifiedUser uuid token (req...regDto)
          savedUser    <- ExceptT $ req...savePreUser $ unUser
          return $ unUser


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
  { loginReqDto     :: LoginDto
  , findUserByEmail :: Text -> IO (Either Text (Maybe User))
  , matchPassword   :: Text -> Text -> Bool
  }

login :: Login
login req@LoginReq{..} = do
  userOptRes <- findUserByEmail $ loginReqDto...loginDtoEmail
  case userOptRes of
    Left e          -> return $ Left e
    Right (Nothing) -> return $ Left "User not found"
    Right (Just u)  ->
      if matchPassword (loginReqDto...loginDtoPass) (u...userPass)
        then
          return $ Right $ AuthToken "todo"
        else
          return $ Left "Passwords do not match"


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


mapRegistrationDataToUnverifiedUser :: UUID -> UUID -> RegisterDto -> UnverUser
mapRegistrationDataToUnverifiedUser uuid token dto =
  UnverUser 
  { uvUserId = UserId uuid
  , uvToken  = VerToken token
  , uvEmail  = dto...rEmail
  , uvPass   = dto...rPass 
  }


mapUnverifiedUserToUser :: UnverUser -> User
mapUnverifiedUserToUser unverUser =
  User 
  { _userId   = unverUser...uvUserId
  , userEmail = unverUser...uvEmail
  , userPass  = unverUser...uvPass
  }

mapUserToLoginUser :: User -> LoggedInUser
mapUserToLoginUser user =
  LoggedInUser
  { loggedInUserId    = user..._userId
  , loggedInUserEmail = user...userEmail
  }