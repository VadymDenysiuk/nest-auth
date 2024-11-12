-- CreateEnum
CREATE TYPE "Provider" AS ENUM ('GOOGLE');

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "provider" "Provider",
ALTER COLUMN "password" DROP NOT NULL;
