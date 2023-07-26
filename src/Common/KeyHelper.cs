using System.Text;

namespace Common
{
    public static class KeyHelper
    {
        public static string GetRootKey()
        {
            return Encoding.Default.GetString(Properties.Resources.grpc_root_key);
        }
    }
}
