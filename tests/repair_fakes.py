"""Synthetic REST adapter using real discord.py Guild/Role/Channel/Member objects."""
from copy import deepcopy

import discord

GUILD = 100000000000001
BOT = 100000000000002
TOP = 100000000000003
ROLE = 100000000000004
OTHER = 100000000000005
CATEGORY = 100000000000006
CHANNEL = 100000000000007
CUSTOM = 100000000000008
MEMBER = 100000000000009


def permission_bits(**flags):
    return str(discord.Permissions(**flags).value)


class Harness:
    def __init__(self):
        self.roles = [
            {"id": str(GUILD), "name": "@everyone", "position": 0, "permissions": permission_bits(view_channel=True, send_messages=True)},
            {"id": str(ROLE), "name": "Reward", "position": 1, "permissions": permission_bits(mention_everyone=True, manage_webhooks=True)},
            {"id": str(OTHER), "name": "Other", "position": 2, "permissions": "0"},
            {"id": str(TOP), "name": "Audit bot", "position": 3,
             "permissions": permission_bits(manage_roles=True, manage_channels=True, manage_webhooks=True, view_channel=True, attach_files=True)},
        ]
        self.channels = [
            {"id": str(CATEGORY), "name": "Community", "type": 4, "position": 0, "permission_overwrites": []},
            {"id": str(CHANNEL), "name": "lounge", "type": 0, "position": 0, "parent_id": str(CATEGORY), "permission_overwrites": []},
            {"id": str(CUSTOM), "name": "custom", "type": 0, "position": 1, "parent_id": str(CATEGORY),
             "permission_overwrites": [{"id": str(OTHER), "type": 0, "allow": permission_bits(attach_files=True), "deny": "0"}]},
        ]
        self.member_roles = {BOT: [str(TOP)], MEMBER: [str(ROLE)]}
        self.guild_extra = {}
        self.writes = []
        self.reads = 0
        self.before_write = None
        self.fail_before = None
        self.fail_after = None
        self.ignore_write = False
        self.client = discord.Client(intents=discord.Intents.none())
        self.client.http = self
        self.client._connection.http = self
        self.client._connection.user = discord.ClientUser(state=self.client._connection, data=self.user(BOT))

    def user(self, uid):
        return {"id": str(uid), "username": "synthetic", "discriminator": "0", "avatar": None, "bot": uid == BOT}

    def role(self, rid=ROLE):
        return next(r for r in self.roles if r["id"] == str(rid))

    def channel(self, cid=CHANNEL):
        return next(c for c in self.channels if c["id"] == str(cid))

    async def get_guild(self, guild_id, **kwargs):
        self.reads += 1
        return {"id": str(GUILD), "name": "Synthetic repair guild", "owner_id": str(MEMBER),
                "roles": deepcopy(self.roles), **deepcopy(self.guild_extra)}

    async def get_roles(self, guild_id):
        return deepcopy(self.roles)

    async def get_all_guild_channels(self, guild_id):
        return deepcopy(self.channels)

    async def get_member(self, guild_id, member_id):
        if member_id not in self.member_roles:
            raise ValueError("Synthetic member unavailable")
        return {"user": self.user(member_id), "roles": self.member_roles[member_id], "joined_at": None,
                "deaf": False, "mute": False, "flags": 0}

    def _start_write(self, kind):
        if self.before_write: self.before_write()
        if self.fail_before: raise self.fail_before
        self.writes.append(kind)

    def _finish_write(self):
        if self.fail_after: raise self.fail_after

    async def edit_role(self, guild_id, role_id, *, reason=None, **kwargs):
        self._start_write("role")
        if not self.ignore_write:
            self.role(role_id).update({k: str(v) if k == "permissions" else v for k, v in kwargs.items()})
        self._finish_write()
        return deepcopy(self.role(role_id))

    def _channel_overwrites(self, cid, overwrites):
        channel = self.channel(cid)
        old = deepcopy(channel["permission_overwrites"])
        channel["permission_overwrites"] = deepcopy(overwrites)
        if channel["type"] == 4:
            for child in self.channels:
                if child.get("parent_id") == str(cid) and child["permission_overwrites"] == old:
                    child["permission_overwrites"] = deepcopy(overwrites)

    async def edit_channel_permissions(self, cid, target, allow, deny, kind, *, reason=None):
        self._start_write("overwrite")
        if not self.ignore_write:
            data = [x for x in self.channel(cid)["permission_overwrites"] if not (x["id"] == str(target) and x["type"] == kind)]
            data.append({"id": str(target), "type": kind, "allow": str(allow), "deny": str(deny)})
            self._channel_overwrites(cid, data)
        self._finish_write()

    async def delete_channel_permissions(self, cid, target, *, reason=None):
        self._start_write("remove_overwrite")
        if not self.ignore_write:
            self._channel_overwrites(cid, [x for x in self.channel(cid)["permission_overwrites"] if x["id"] != str(target)])
        self._finish_write()

    async def edit_channel(self, cid, *, reason=None, **kwargs):
        self._start_write("sync")
        if not self.ignore_write and "permission_overwrites" in kwargs:
            self._channel_overwrites(cid, kwargs["permission_overwrites"])
        self._finish_write()
        return deepcopy(self.channel(cid))

    async def move_role_position(self, guild_id, positions, *, reason=None):
        self._start_write("positions")
        if not self.ignore_write:
            for item in positions: self.role(item["id"])["position"] = item["position"]
        self._finish_write()
        return deepcopy(self.roles)

    async def delete_channel(self, cid, *, reason=None):
        self._start_write("delete")
        if not self.ignore_write: self.channels = [c for c in self.channels if c["id"] != str(cid)]
        self._finish_write()

    async def close(self):
        pass
